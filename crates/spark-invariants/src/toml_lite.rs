//! A reader for the TOML subset the manifests in `docs/` actually use.
//!
//! Tables, arrays of tables, string / integer / string-array values, multi-line
//! basic strings, comments. No dates, no floats, no inline tables. Anything
//! outside that subset is a parse error rather than a silent skip, so a manifest
//! cannot quietly stop being checked.

use std::collections::BTreeMap;

/// A parsed value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// A string.
    Str(String),
    /// An integer.
    Int(i64),
    /// An array of values.
    Arr(Vec<Value>),
}

impl Value {
    /// The string contents, or `None` for other kinds.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    /// The elements as strings, or an empty vec for other kinds.
    pub fn as_str_vec(&self) -> Vec<String> {
        match self {
            Value::Arr(v) => v
                .iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// A parsed document, flattened to dotted paths.
///
/// Arrays of tables are indexed: `[[crate]]` entries become `crate[0].name`,
/// `crate[1].name`, and so on.
#[derive(Debug, Default)]
pub struct Doc {
    map: BTreeMap<String, Value>,
}

impl Doc {
    /// Look up one path.
    pub fn get(&self, path: &str) -> Option<&Value> {
        self.map.get(path)
    }
    /// Look up one path as a string.
    pub fn str(&self, path: &str) -> Option<&str> {
        self.get(path).and_then(Value::as_str)
    }
    /// Look up one path as a list of strings; empty when absent.
    pub fn strs(&self, path: &str) -> Vec<String> {
        self.get(path).map(Value::as_str_vec).unwrap_or_default()
    }
    /// How many `[[name]]` entries the document holds.
    pub fn count(&self, name: &str) -> usize {
        let prefix = format!("{name}[");
        let mut n = 0;
        while self
            .map
            .keys()
            .any(|k| k.starts_with(&format!("{prefix}{n}].")))
        {
            n += 1;
        }
        n
    }
    /// Every key present, for diagnostics.
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.map.keys()
    }
}

/// Parse the supported subset. Returns the first error encountered, with a line number.
pub fn parse(src: &str) -> Result<Doc, String> {
    let mut doc = Doc::default();
    let mut prefix = String::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let lines: Vec<&str> = src.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let lineno = i + 1;
        let raw = lines[i];
        i += 1;
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix("[[") {
            let name = rest
                .strip_suffix("]]")
                .ok_or_else(|| format!("line {lineno}: unterminated [[table]]"))?
                .trim()
                .to_string();
            let n = counts.entry(name.clone()).or_insert(0);
            prefix = format!("{name}[{n}]");
            *n += 1;
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            prefix = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("line {lineno}: unterminated [table]"))?
                .trim()
                .to_string();
            continue;
        }

        let (key, first) = line
            .split_once('=')
            .ok_or_else(|| format!("line {lineno}: expected `key = value`, got `{line}`"))?;
        let key = key.trim().trim_matches('"').to_string();
        let mut val = first.trim().to_string();

        // A multi-line basic string. Comments are not stripped inside one: a `#`
        // in prose is a `#`, not the start of a comment.
        if val.starts_with("\"\"\"") {
            let mut body = raw[raw.find("\"\"\"").expect("just matched") + 3..].to_string();
            if body.trim_end().ends_with("\"\"\"") && !body.trim().is_empty() {
                // Opened and closed on one line.
                let end = body.rfind("\"\"\"").expect("checked");
                body.truncate(end);
            } else {
                loop {
                    if i >= lines.len() {
                        return Err(format!("line {lineno}: unterminated multi-line string"));
                    }
                    let l = lines[i];
                    i += 1;
                    if let Some(end) = l.find("\"\"\"") {
                        body.push('\n');
                        body.push_str(&l[..end]);
                        break;
                    }
                    body.push('\n');
                    body.push_str(l);
                }
            }
            // TOML trims a newline immediately after the opening delimiter.
            let body = body.strip_prefix('\n').unwrap_or(&body).to_string();
            let path = if prefix.is_empty() {
                key
            } else {
                format!("{prefix}.{key}")
            };
            doc.map.insert(path, Value::Str(body));
            continue;
        }

        // An array may span lines; consume until the brackets balance.
        if val.starts_with('[') {
            while depth(&val) > 0 {
                if i >= lines.len() {
                    return Err(format!("line {lineno}: unterminated array"));
                }
                val.push(' ');
                val.push_str(strip_comment(lines[i]).trim());
                i += 1;
            }
        }

        let path = if prefix.is_empty() {
            key
        } else {
            format!("{prefix}.{key}")
        };
        doc.map.insert(path, parse_value(&val, lineno)?);
    }
    Ok(doc)
}

fn depth(s: &str) -> i32 {
    let mut d = 0;
    let mut in_str = false;
    for c in s.chars() {
        match c {
            '"' => in_str = !in_str,
            '[' if !in_str => d += 1,
            ']' if !in_str => d -= 1,
            _ => {}
        }
    }
    d
}

fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    for (idx, c) in line.char_indices() {
        match c {
            '"' => in_str = !in_str,
            '#' if !in_str => return &line[..idx],
            _ => {}
        }
    }
    line
}

fn parse_value(s: &str, lineno: usize) -> Result<Value, String> {
    let s = s.trim();
    if let Some(inner) = s.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        let mut out = Vec::new();
        for part in split_top(inner) {
            let p = part.trim();
            if !p.is_empty() {
                out.push(parse_value(p, lineno)?);
            }
        }
        return Ok(Value::Arr(out));
    }
    if let Some(inner) = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        return Ok(Value::Str(inner.to_string()));
    }
    s.parse::<i64>()
        .map(Value::Int)
        .map_err(|_| format!("line {lineno}: unsupported value `{s}`"))
}

fn split_top(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut in_str, mut d) = (Vec::new(), String::new(), false, 0);
    for c in s.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            '[' if !in_str => {
                d += 1;
                cur.push(c);
            }
            ']' if !in_str => {
                d -= 1;
                cur.push(c);
            }
            ',' if !in_str && d == 0 => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}
