//! Atom text constructs ↔ the Markdown the feed shows, as in monocles chat for Android
//! (`AtomText`, `MarkdownToXhtml`, `Post.extractHashtags`).
//!
//! Movim and other XEP-0277 clients publish `<content type="xhtml">` with an XHTML `<div>`;
//! reading only the element text ran paragraphs together and dropped links. Only structure is
//! carried over (paragraphs, line breaks, lists, quotes, emphasis, links); markup that isn't
//! understood contributes just its text. Links are limited to http(s)/xmpp.

use minidom::{Element, Node};
use pulldown_cmark::{Event, Parser, Tag, TagEnd};

pub const NS_XHTML: &str = "http://www.w3.org/1999/xhtml";

fn is_safe_link(href: &str) -> bool {
    let lower = href.trim().to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://") || lower.starts_with("xmpp:")
}

/// All text below `e`, in document order.
fn deep_text(e: &Element) -> String {
    let mut s = String::new();
    for node in e.nodes() {
        match node {
            Node::Text(t) => s.push_str(t),
            Node::Element(c) => s.push_str(&deep_text(c)),
        }
    }
    s
}

// --- Atom → Markdown -----------------------------------------------------------------------

/// The construct as Markdown, or None if it has no text.
pub fn to_markdown(construct: &Element) -> Option<String> {
    let kind = construct.attr("type").unwrap_or_default().to_ascii_lowercase();
    let result = match kind.as_str() {
        "xhtml" => {
            let div = construct
                .children()
                .find(|c| c.name() == "div")
                .unwrap_or(construct);
            let mut out = String::new();
            append_children(div, &mut out, &mut ListState::default());
            tidy(&out)
        }
        "html" | "text/html" => tidy(&html_to_text(&construct.text())),
        _ => construct.text(),
    };
    let trimmed = result.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Escaped HTML (type="html"): keeps paragraph and line breaks, drops the tags. Rare in
/// practice, so no attempt is made to keep links or emphasis.
fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(start) = rest.find('<') {
        out.push_str(&rest[..start]);
        let Some(end) = rest[start..].find('>') else {
            rest = "";
            break;
        };
        let tag = rest[start + 1..start + end].trim().to_ascii_lowercase();
        let name = tag.trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/').next().unwrap_or("");
        if name == "br" {
            out.push('\n');
        } else if tag.starts_with('/')
            && matches!(name, "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote")
        {
            out.push_str("\n\n");
        }
        rest = &rest[start + end + 1..];
    }
    out.push_str(rest);
    out.replace("&nbsp;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

#[derive(Default)]
struct ListState {
    ordered: bool,
    counter: u32,
}

fn collapse_ws(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_ws = false;
    for c in text.chars() {
        if matches!(c, ' ' | '\t' | '\r' | '\n' | '\x0c') {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

fn append_children(e: &Element, out: &mut String, list: &mut ListState) {
    for node in e.nodes() {
        match node {
            Node::Element(c) => append_element(c, out, list),
            Node::Text(t) => out.push_str(&collapse_ws(t)),
        }
    }
}

fn inline(e: &Element, list: &mut ListState) -> String {
    let mut s = String::new();
    append_children(e, &mut s, list);
    s
}

fn wrap(out: &mut String, marker: &str, text: &str) {
    let t = text.trim();
    if !t.is_empty() {
        out.push_str(marker);
        out.push_str(t);
        out.push_str(marker);
    }
}

fn markdown_link(out: &mut String, label: &str, href: &str) {
    out.push('[');
    out.push_str(&label.replace(']', "\\]"));
    out.push_str("](");
    out.push_str(&href.replace(')', "%29"));
    out.push(')');
}

fn append_element(e: &Element, out: &mut String, list: &mut ListState) {
    let name = e.name().to_ascii_lowercase();
    match name.as_str() {
        "br" => out.push('\n'),
        "p" | "div" | "section" | "article" | "figure" | "figcaption" => {
            block(out);
            append_children(e, out, list);
            block(out);
        }
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => {
            block(out);
            let level = (name.as_bytes()[1] - b'0') as usize;
            out.push_str(&"#".repeat(level));
            out.push(' ');
            out.push_str(&inline(e, list));
            block(out);
        }
        "blockquote" => {
            block(out);
            for line in tidy(&inline(e, list)).split('\n') {
                out.push_str("> ");
                out.push_str(line);
                out.push('\n');
            }
            block(out);
        }
        "pre" => {
            block(out);
            out.push_str("```\n");
            out.push_str(deep_text(e).trim());
            out.push_str("\n```");
            block(out);
        }
        "ul" | "ol" => {
            block(out);
            let mut nested = ListState { ordered: name == "ol", counter: 0 };
            append_children(e, out, &mut nested);
            block(out);
        }
        "li" => {
            line_break(out);
            if list.ordered {
                list.counter += 1;
                out.push_str(&format!("{}. ", list.counter));
            } else {
                out.push_str("- ");
            }
            out.push_str(inline(e, list).trim());
            out.push('\n');
        }
        "strong" | "b" => wrap(out, "**", &inline(e, list)),
        "em" | "i" => wrap(out, "*", &inline(e, list)),
        "del" | "s" => wrap(out, "~~", &inline(e, list)),
        "code" => wrap(out, "`", &deep_text(e)),
        "a" => {
            let text = inline(e, list).trim().to_string();
            match e.attr("href").map(str::trim).filter(|h| is_safe_link(h)) {
                Some(href) => {
                    let label = if text.is_empty() { href } else { &text };
                    if label == href {
                        out.push_str(href);
                    } else {
                        markdown_link(out, label, href);
                    }
                }
                None => out.push_str(&text),
            }
        }
        "img" => {
            let alt = e.attr("alt").unwrap_or_default().trim();
            match e.attr("src").map(str::trim).filter(|s| is_safe_link(s)) {
                // Rendered as a link: inline remote images would load without the user asking.
                Some(src) => markdown_link(out, if alt.is_empty() { src } else { alt }, src),
                None => out.push_str(alt),
            }
        }
        "script" | "style" => {}
        _ => append_children(e, out, list),
    }
}

fn trim_trailing_spaces(out: &mut String) {
    while out.ends_with(' ') {
        out.pop();
    }
}

fn block(out: &mut String) {
    trim_trailing_spaces(out);
    if out.is_empty() {
        return;
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.ends_with("\n\n") {
        out.push('\n');
    }
}

fn line_break(out: &mut String) {
    trim_trailing_spaces(out);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
}

fn tidy(s: &str) -> String {
    let lines: Vec<&str> = s.split('\n').map(|l| l.trim_matches(' ')).collect();
    let joined = lines.join("\n");
    // At most one blank line in a row.
    let mut out = String::with_capacity(joined.len());
    let mut newlines = 0;
    for c in joined.chars() {
        if c == '\n' {
            newlines += 1;
            if newlines > 2 {
                continue;
            }
        } else {
            newlines = 0;
        }
        out.push(c);
    }
    out.trim().to_string()
}

// --- Markdown → XHTML ----------------------------------------------------------------------

/// Renders a post's Markdown as the XHTML `<div>` of an Atom `<content type="xhtml">`, which
/// is the only content Movim displays. Built from the parse tree, so the result is well-formed
/// and text is escaped by the serializer. Raw HTML in the source is kept as literal text, links
/// are limited to http(s)/xmpp, and every newline is kept as a line break.
pub fn markdown_to_xhtml_div(markdown: &str) -> Element {
    // Open elements; `None` is a transparent wrapper (e.g. an unsafe link) whose children go
    // to the element below it.
    let mut stack: Vec<Option<Element>> = vec![Some(Element::bare("div", NS_XHTML))];
    let mut in_code_block = false;
    let mut in_html_block = false;

    fn top(stack: &mut [Option<Element>]) -> &mut Element {
        stack.iter_mut().rev().find_map(|e| e.as_mut()).expect("root div")
    }
    fn text(stack: &mut [Option<Element>], t: &str) {
        if !t.is_empty() {
            top(stack).append_text_node(t);
        }
    }
    fn push(stack: &mut Vec<Option<Element>>, name: &str) {
        stack.push(Some(Element::bare(name, NS_XHTML)));
    }

    if markdown.trim().is_empty() {
        return stack.pop().flatten().expect("root div");
    }

    for event in Parser::new(markdown) {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => push(&mut stack, "p"),
                Tag::Heading { level, .. } => push(&mut stack, &format!("h{}", level as usize)),
                Tag::BlockQuote(_) => push(&mut stack, "blockquote"),
                Tag::CodeBlock(_) => {
                    in_code_block = true;
                    push(&mut stack, "pre");
                    push(&mut stack, "code");
                }
                Tag::HtmlBlock => {
                    in_html_block = true;
                    push(&mut stack, "p");
                }
                Tag::List(Some(start)) => {
                    let mut ol = Element::builder("ol", NS_XHTML);
                    if start != 1 {
                        ol = ol.attr(crate::ncname("start"), start.to_string());
                    }
                    stack.push(Some(ol.build()));
                }
                Tag::List(None) => push(&mut stack, "ul"),
                Tag::Item => push(&mut stack, "li"),
                Tag::Emphasis => push(&mut stack, "em"),
                Tag::Strong => push(&mut stack, "strong"),
                Tag::Strikethrough => push(&mut stack, "del"),
                // Images become links too: the attachment is shown separately, and remote
                // images should only load when the reader asks for them.
                Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. } => {
                    if is_safe_link(&dest_url) {
                        let a = Element::builder("a", NS_XHTML)
                            .attr(crate::ncname("href"), dest_url.trim().to_string())
                            .build();
                        stack.push(Some(a));
                    } else {
                        stack.push(None);
                    }
                }
                _ => stack.push(None),
            },
            Event::End(end) => {
                if let TagEnd::CodeBlock = end {
                    in_code_block = false;
                    // Close <code> and <pre>; drop the block's trailing newline.
                    if let Some(Some(mut code)) = stack.pop() {
                        let literal = code.text();
                        let literal = literal.strip_suffix('\n').unwrap_or(&literal).to_string();
                        code = Element::bare("code", NS_XHTML);
                        code.append_text_node(literal);
                        if let Some(Some(pre)) = stack.last_mut() {
                            pre.append_child(code);
                        }
                    }
                }
                if let TagEnd::HtmlBlock = end {
                    in_html_block = false;
                    if let Some(Some(p)) = stack.last_mut() {
                        let literal = p.text();
                        let literal = literal.strip_suffix('\n').unwrap_or(&literal).to_string();
                        *p = Element::bare("p", NS_XHTML);
                        p.append_text_node(literal);
                    }
                }
                let Some(closed) = stack.pop() else { break };
                if let Some(mut el) = closed {
                    if el.name() == "a" && el.nodes().next().is_none() {
                        let href = el.attr("href").unwrap_or_default().to_string();
                        el.append_text_node(href);
                    }
                    if stack.is_empty() {
                        // Unbalanced input can't happen with pulldown-cmark; keep the root.
                        stack.push(Some(el));
                        break;
                    }
                    top(&mut stack).append_child(el);
                }
            }
            Event::Text(t) => text(&mut stack, &t),
            Event::Code(c) => {
                let mut code = Element::bare("code", NS_XHTML);
                code.append_text_node(c.to_string());
                top(&mut stack).append_child(code);
            }
            // Never pass raw HTML through; show it as written.
            Event::Html(h) | Event::InlineHtml(h) => {
                let _ = in_html_block;
                text(&mut stack, &h)
            }
            Event::SoftBreak | Event::HardBreak => {
                if in_code_block {
                    text(&mut stack, "\n");
                } else {
                    top(&mut stack).append_child(Element::bare("br", NS_XHTML));
                }
            }
            Event::Rule => {
                top(&mut stack).append_child(Element::bare("hr", NS_XHTML));
            }
            _ => {}
        }
    }
    while stack.len() > 1 {
        if let Some(Some(el)) = stack.pop() {
            top(&mut stack).append_child(el);
        }
    }
    stack.pop().flatten().expect("root div")
}

// --- hashtags ------------------------------------------------------------------------------

fn is_tag_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Hashtags in `text`, lower-cased, without the '#', each once — for publishing as Atom
/// categories. A '#' right after a letter, digit, '_', '#', '@', '/' or '&' (URL anchors,
/// e-mail-like strings, entities) doesn't start one.
pub fn extract_hashtags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '#' {
            let prev_ok = i == 0 || !(is_tag_char(chars[i - 1]) || matches!(chars[i - 1], '#' | '@' | '/' | '&'));
            let mut j = i + 1;
            while j < chars.len() && is_tag_char(chars[j]) {
                j += 1;
            }
            if prev_ok && j > i + 1 {
                let tag: String = chars[i + 1..j].iter().collect::<String>().to_lowercase();
                if !tags.contains(&tag) {
                    tags.push(tag);
                }
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    const ATOM: &str = "http://www.w3.org/2005/Atom";

    fn parse(xml: &str) -> Element {
        xml.parse().unwrap()
    }

    #[test]
    fn xhtml_becomes_markdown_with_paragraphs_and_safe_links() {
        let content = parse(&format!(
            "<content xmlns='{ATOM}' type='xhtml'><div xmlns='{NS_XHTML}'><p>Hello <strong>world</strong>, see \
             <a href='https://example.org/x'>this</a></p><p>Second\n   paragraph</p>\
             <a href='javascript:alert(1)'>click</a></div></content>"
        ));
        assert_eq!(
            to_markdown(&content).unwrap(),
            "Hello **world**, see [this](https://example.org/x)\n\nSecond paragraph\n\nclick"
        );
    }

    #[test]
    fn text_construct_is_taken_as_is() {
        let title = parse(&format!("<title xmlns='{ATOM}' type='text'>a *plain* title</title>"));
        assert_eq!(to_markdown(&title).unwrap(), "a *plain* title");
    }

    #[test]
    fn escaped_html_keeps_breaks_and_drops_tags() {
        let content = parse(&format!(
            "<content xmlns='{ATOM}' type='html'>&lt;p&gt;One &amp;amp; two&lt;/p&gt;&lt;p&gt;three&lt;br/&gt;four&lt;/p&gt;</content>"
        ));
        assert_eq!(to_markdown(&content).unwrap(), "One & two\n\nthree\nfour");
    }

    #[test]
    fn markdown_renders_to_safe_xhtml() {
        let div = markdown_to_xhtml_div("a\nb **bold** [x](https://e.org) [bad](javascript:1) <b>raw</b>\n\n- one\n- two");
        let xml = String::from(&div);
        assert!(xml.contains("<br"), "{xml}");
        assert!(xml.contains("<strong>bold</strong>"), "{xml}");
        assert!(xml.contains("href='https://e.org'"), "{xml}");
        assert!(!xml.contains("javascript"), "{xml}");
        assert!(xml.contains("&lt;b&gt;raw&lt;/b&gt;"), "{xml}");
        assert!(xml.contains("<li>one</li>"), "{xml}");
        // And back.
        let content = Element::builder("content", ATOM).attr(crate::ncname("type"), "xhtml").append(div).build();
        let md = to_markdown(&content).unwrap();
        assert!(md.starts_with("a\nb **bold** [x](https://e.org) bad"), "{md}");
    }

    #[test]
    fn hashtags_are_extracted_once() {
        assert_eq!(
            extract_hashtags("#XMPP rocks, #xmpp again, mail@#nothere, https://x.org/#anchor and #über_cool"),
            vec!["xmpp", "über_cool"]
        );
    }
}
