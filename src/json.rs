//! One JSON object per line, written by hand.
//!
//! The project has no `serde`, and the event schema is a handful of flat
//! objects, so a serializer would be more code than the events themselves.
//! What is not negotiable is that the escaping is correct: a file name with a
//! quote or a newline in it must not be able to break the stream, so the
//! escaping lives in one place and has its own tests.

/// Escape a string so it can be placed inside a JSON string literal.
/// The result carries no quotes of its own.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A JSON object under construction. Fields keep the order they are added in,
/// so the stream is stable and easy to read by eye.
#[derive(Debug, Default)]
pub struct Object {
    fields: Vec<String>,
}

impl Object {
    /// A new object of the given type.
    pub fn new(kind: &str) -> Object {
        Object {
            fields: vec![format!("\"type\":\"{}\"", escape(kind))],
        }
    }

    /// A string field.
    pub fn text(&mut self, name: &str, value: &str) -> &mut Object {
        self.fields
            .push(format!("\"{}\":\"{}\"", escape(name), escape(value)));
        self
    }

    /// A number field.
    pub fn number(&mut self, name: &str, value: u64) -> &mut Object {
        self.fields.push(format!("\"{}\":{}", escape(name), value));
        self
    }

    /// The finished object.
    pub fn finish(&self) -> String {
        format!("{{{}}}", self.fields.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_backslashes_and_control_characters_are_escaped() {
        assert_eq!(escape("plain"), "plain");
        assert_eq!(escape("say \"hi\""), "say \\\"hi\\\"");
        assert_eq!(escape("a\\b"), "a\\\\b");
        assert_eq!(escape("line\nbreak"), "line\\nbreak");
        assert_eq!(escape("tab\there"), "tab\\there");
        assert_eq!(escape("cr\r"), "cr\\r");
        assert_eq!(escape("bell\u{07}"), "bell\\u0007");
        assert_eq!(escape("nul\u{00}"), "nul\\u0000");
        // Non-ASCII text is valid UTF-8 and needs no escaping.
        assert_eq!(escape("café ✓"), "café ✓");
    }

    #[test]
    fn an_object_keeps_its_fields_in_order() {
        let mut object = Object::new("plan");
        object
            .text("action", "create")
            .text("path", "a/b.txt")
            .number("size", 12);
        assert_eq!(
            object.finish(),
            r#"{"type":"plan","action":"create","path":"a/b.txt","size":12}"#
        );
    }

    #[test]
    fn a_hostile_path_cannot_break_the_stream() {
        let mut object = Object::new("plan");
        object.text("path", "we\"ird\\name\n.txt");
        let line = object.finish();
        assert_eq!(line, r#"{"type":"plan","path":"we\"ird\\name\n.txt"}"#);
        // The line must still be one line.
        assert!(!line.contains('\n'));
    }
}
