//! A tiny, dependency-free JSON reader — just enough to parse advisory input.
//!
//! Supports objects, arrays, strings, numbers, booleans, and null. Not a
//! general-purpose serializer; it exists so the Rust port stays std-only.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn as_array(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&BTreeMap<String, Json>> {
        match self {
            Json::Obj(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Json> {
        self.as_object().and_then(|m| m.get(key))
    }
}

pub fn parse(input: &str) -> Result<Json, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut p = Parser { chars, pos: 0 };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.chars.len() {
        return Err("trailing data after JSON value".to_string());
    }
    Ok(v)
}

struct Parser {
    chars: Vec<char>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }
    fn next(&mut self) -> Option<char> {
        let c = self.chars.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c.is_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('{') => self.parse_object(),
            Some('[') => self.parse_array(),
            Some('"') => Ok(Json::Str(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            other => Err(format!("unexpected token: {:?}", other)),
        }
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        self.next(); // {
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.next();
            return Ok(Json::Obj(map));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some('"') {
                return Err("expected string key in object".to_string());
            }
            let key = self.parse_string()?;
            self.skip_ws();
            if self.next() != Some(':') {
                return Err("expected ':' in object".to_string());
            }
            let val = self.parse_value()?;
            map.insert(key, val);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some('}') => break,
                other => return Err(format!("expected ',' or '}}' got {:?}", other)),
            }
        }
        Ok(Json::Obj(map))
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        self.next(); // [
        let mut arr = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.next();
            return Ok(Json::Arr(arr));
        }
        loop {
            let val = self.parse_value()?;
            arr.push(val);
            self.skip_ws();
            match self.next() {
                Some(',') => continue,
                Some(']') => break,
                other => return Err(format!("expected ',' or ']' got {:?}", other)),
            }
        }
        Ok(Json::Arr(arr))
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.next(); // opening quote
        let mut s = String::new();
        while let Some(c) = self.next() {
            match c {
                '"' => return Ok(s),
                '\\' => match self.next() {
                    Some('"') => s.push('"'),
                    Some('\\') => s.push('\\'),
                    Some('/') => s.push('/'),
                    Some('n') => s.push('\n'),
                    Some('t') => s.push('\t'),
                    Some('r') => s.push('\r'),
                    Some('b') => s.push('\u{08}'),
                    Some('f') => s.push('\u{0C}'),
                    Some('u') => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            let h = self.next().ok_or("bad unicode escape")?;
                            code = code * 16 + h.to_digit(16).ok_or("bad hex digit")?;
                        }
                        s.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                    }
                    other => return Err(format!("bad escape: {:?}", other)),
                },
                _ => s.push(c),
            }
        }
        Err("unterminated string".to_string())
    }

    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.chars[self.pos..].starts_with(&['t', 'r', 'u', 'e']) {
            self.pos += 4;
            Ok(Json::Bool(true))
        } else if self.chars[self.pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
            self.pos += 5;
            Ok(Json::Bool(false))
        } else {
            Err("invalid boolean literal".to_string())
        }
    }

    fn parse_null(&mut self) -> Result<Json, String> {
        if self.chars[self.pos..].starts_with(&['n', 'u', 'l', 'l']) {
            self.pos += 4;
            Ok(Json::Null)
        } else {
            Err("invalid null literal".to_string())
        }
    }

    fn parse_number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.next();
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-' {
                self.next();
            } else {
                break;
            }
        }
        let text: String = self.chars[start..self.pos].iter().collect();
        text.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("invalid number: {}", text))
    }
}
