//! XEP-0393 (Message Styling) v1.1.1, same parser as monocles Android (`ImStyleParser`).
//!
//! The text is first split into blocks - quotations, preformatted text blocks and plain lines -
//! and spans are then parsed inside each plain line, lazily from the beginning. Quotations are
//! parsed recursively with the '>' and the first whitespace character of every line removed.
//! Positions are char indices into the original text; the directives stay in the text and are
//! rendered with the span they belong to (as the XEP recommends).

pub const NS_STYLING: &str = "urn:xmpp:styling:0";

const KEYWORDS: [char; 4] = ['*', '_', '~', '`'];
const PREFORMATTED_SPAN: char = '`';
const QUOTE: char = '>';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Strong,
    Emphasis,
    Strike,
    PreformattedSpan,
    PreformattedBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Style {
    pub kind: Kind,
    /// First char of the opening directive.
    pub start: usize,
    /// Last char of the closing directive, or of the block for an unclosed preformatted block.
    pub end: usize,
    /// False for a preformatted block that runs to the end of its parent block.
    pub closed: bool,
}

fn kind_of(c: char) -> Kind {
    match c {
        '*' => Kind::Strong,
        '_' => Kind::Emphasis,
        '~' => Kind::Strike,
        _ => Kind::PreformattedSpan,
    }
}

/// A view on (possibly non-contiguous) chars of the original text.
struct Region<'a> {
    text: &'a [char],
    positions: Vec<usize>,
}

impl Region<'_> {
    fn len(&self) -> usize {
        self.positions.len()
    }
    fn at(&self, i: usize) -> char {
        self.text[self.positions[i]]
    }
    fn line_end(&self, i: usize) -> usize {
        (i..self.len()).find(|&k| self.at(k) == '\n').unwrap_or(self.len())
    }
    fn starts_with(&self, i: usize, prefix: &str) -> bool {
        let p: Vec<char> = prefix.chars().collect();
        i + p.len() <= self.len() && p.iter().enumerate().all(|(k, c)| self.at(i + k) == *c)
    }
}

pub fn parse(text: &str) -> Vec<Style> {
    let chars: Vec<char> = text.chars().collect();
    let mut styles = Vec::new();
    let region = Region { text: &chars, positions: (0..chars.len()).collect() };
    parse_blocks(&region, &mut styles);
    styles
}

fn parse_blocks(region: &Region, styles: &mut Vec<Style>) {
    let mut i = 0;
    while i < region.len() {
        let line_end = region.line_end(i);
        if region.at(i) == QUOTE {
            i = parse_quotation(region, i, styles);
        } else if region.starts_with(i, "```") {
            i = parse_preformatted_block(region, i, styles);
        } else {
            parse_spans(region, i, line_end, styles);
            i = line_end + 1;
        }
    }
}

fn parse_quotation(region: &Region, mut i: usize, styles: &mut Vec<Style>) -> usize {
    let mut child = Vec::new();
    while i < region.len() && region.at(i) == QUOTE {
        let line_end = region.line_end(i);
        let mut content = i + 1;
        if content < line_end && region.at(content).is_whitespace() {
            content += 1;
        }
        child.extend((content..line_end).map(|k| region.positions[k]));
        let next_quoted = line_end + 1 < region.len() && region.at(line_end + 1) == QUOTE;
        if next_quoted {
            child.push(region.positions[line_end]);
        }
        i = line_end + 1;
        if !next_quoted {
            break;
        }
    }
    parse_blocks(&Region { text: region.text, positions: child }, styles);
    i
}

fn parse_preformatted_block(region: &Region, start: usize, styles: &mut Vec<Style>) -> usize {
    let mut line = region.line_end(start) + 1;
    while line < region.len() {
        let line_end = region.line_end(line);
        if line_end - line == 3 && region.starts_with(line, "```") {
            styles.push(Style {
                kind: Kind::PreformattedBlock,
                start: region.positions[start],
                end: region.positions[line_end - 1],
                closed: true,
            });
            return line_end + 1;
        }
        line = line_end + 1;
    }
    styles.push(Style {
        kind: Kind::PreformattedBlock,
        start: region.positions[start],
        end: region.positions[region.len() - 1],
        closed: false,
    });
    region.len()
}

fn parse_spans(region: &Region, from: usize, to: usize, styles: &mut Vec<Style>) {
    // A directive without a closing candidate up to the end of the line can't be closed from a
    // later position either; remembering that keeps hostile input linear.
    let mut unclosable = [false; KEYWORDS.len()];
    let mut i = from;
    while i < to {
        let c = region.at(i);
        let Some(keyword) = KEYWORDS.iter().position(|k| *k == c) else {
            i += 1;
            continue;
        };
        if unclosable[keyword] || !is_opening(region, i, from, to) {
            i += 1;
            continue;
        }
        let Some(close) = (i + 1..to).find(|&k| region.at(k) == c && !region.at(k - 1).is_whitespace()) else {
            unclosable[keyword] = true;
            i += 1;
            continue;
        };
        if close == i + 1 {
            i += 1; // an empty span: neither directive is valid
            continue;
        }
        styles.push(Style { kind: kind_of(c), start: region.positions[i], end: region.positions[close], closed: true });
        if c != PREFORMATTED_SPAN {
            parse_spans(region, i + 1, close, styles);
        }
        i = close + 1;
    }
}

/// At the beginning of the parent block, after whitespace or after a different opening
/// directive - and not followed by whitespace.
fn is_opening(region: &Region, i: usize, from: usize, to: usize) -> bool {
    if i + 1 >= to || region.at(i + 1).is_whitespace() {
        return false;
    }
    is_opening_position(region, i, from)
}

fn is_opening_position(region: &Region, i: usize, from: usize) -> bool {
    if i == from {
        return true;
    }
    let previous = region.at(i - 1);
    previous.is_whitespace()
        || (KEYWORDS.contains(&previous) && previous != region.at(i) && is_opening_position(region, i - 1, from))
}

/// A detected link: first and last char of the link text, and its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub start: usize,
    pub end: usize,
    pub href: String,
}

/// Link prefixes recognised in message text, with the scheme prepended to the target.
const LINK_PREFIXES: [(&str, &str); 4] = [("https://", ""), ("http://", ""), ("xmpp:", ""), ("www.", "https://")];

fn starts_with_ci(chars: &[char], i: usize, prefix: &str) -> bool {
    let mut k = i;
    for p in prefix.chars() {
        if k >= chars.len() || chars[k].to_ascii_lowercase() != p {
            return false;
        }
        k += 1;
    }
    true
}

/// Web (`http(s)://`, `www.`) and `xmpp:` links in plain text. A link starts at a word
/// boundary and runs to whitespace or `<>"\``; trailing punctuation and styling directives are
/// not part of it, nor is a closing parenthesis without a matching opening one inside the link.
pub fn find_links(text: &str) -> Vec<Link> {
    let chars: Vec<char> = text.chars().collect();
    let mut links = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let boundary = i == 0 || {
            let p = chars[i - 1];
            !(p.is_alphanumeric() || matches!(p, '@' | '/' | '.' | ':' | '-'))
        };
        let prefix = if boundary { LINK_PREFIXES.iter().find(|(p, _)| starts_with_ci(&chars, i, p)) } else { None };
        let Some((prefix, scheme)) = prefix else {
            i += 1;
            continue;
        };
        let body_start = i + prefix.chars().count();
        let mut end = body_start;
        while end < chars.len() && !chars[end].is_whitespace() && !matches!(chars[end], '<' | '>' | '"' | '`') {
            end += 1;
        }
        // Trim trailing punctuation, directives and unbalanced ')' (counted once, so hostile
        // input stays linear).
        let open_parens = chars[i..end].iter().filter(|&&c| c == '(').count();
        let mut close_parens = chars[i..end].iter().filter(|&&c| c == ')').count();
        while end > body_start {
            let c = chars[end - 1];
            let unbalanced_paren = c == ')' && close_parens > open_parens;
            if matches!(c, '.' | ',' | ';' | ':' | '!' | '?' | '\'' | '*' | '_' | '~') || unbalanced_paren {
                if c == ')' {
                    close_parens -= 1;
                }
                end -= 1;
            } else {
                break;
            }
        }
        let rest = &chars[body_start..end];
        let valid = rest.first().is_some_and(|c| c.is_alphanumeric())
            && (*prefix != "www." || rest.contains(&'.'));
        if !valid {
            i = end.max(i + 1);
            continue;
        }
        let link_text: String = chars[i..end].iter().collect();
        links.push(Link { start: i, end: end - 1, href: format!("{scheme}{link_text}") });
        i = end;
    }
    links
}

fn push_escaped(out: &mut String, c: char) {
    match c {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#39;"),
        _ => out.push(c),
    }
}

fn push_link_open(out: &mut String, link: &Link) {
    out.push_str("<a href=\"");
    link.href.chars().for_each(|c| push_escaped(out, c));
    out.push_str("\">");
}

/// The body as Qt rich text, or `None` when there is nothing to mark up (render it as plain
/// text then). Every character of the body is escaped; the only markup emitted is the XEP-0393
/// styling itself (when `styled`; off for `<unstyled/>` messages) and links (see
/// [`find_links`]; never inside preformatted text).
pub fn to_html(text: &str, styled: bool) -> Option<String> {
    let mut styles = if styled { parse(text) } else { Vec::new() };
    // Styles are laminar (nested or disjoint): open outer first, close inner first.
    styles.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    // Code ranges never nest in each other, so they come out disjoint and sorted; links are
    // sorted too, so one forward pass drops every link overlapping code (linear on hostile input).
    let code: Vec<(usize, usize)> = styles
        .iter()
        .filter(|s| matches!(s.kind, Kind::PreformattedSpan | Kind::PreformattedBlock))
        .map(|s| (s.start, s.end))
        .collect();
    let mut c = 0;
    let links: Vec<Link> = find_links(text)
        .into_iter()
        .filter(|l| {
            while c < code.len() && code[c].1 < l.start {
                c += 1;
            }
            !(c < code.len() && code[c].0 <= l.end)
        })
        .collect();
    if styles.is_empty() && links.is_empty() {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len() + 64);
    out.push_str("<span style=\"white-space: pre-wrap;\">");
    let mut open: Vec<&Style> = Vec::new();
    let mut next = 0;
    let mut next_link = 0;
    // The link currently open, if any. Style tags inside a link close and reopen the <a> around
    // them so the markup stays properly nested.
    let mut in_link: Option<&Link> = None;
    for (i, c) in chars.iter().enumerate() {
        if next < styles.len() && styles[next].start == i {
            if in_link.is_some() {
                out.push_str("</a>");
            }
            while next < styles.len() && styles[next].start == i {
                out.push_str(tag(styles[next].kind, false));
                open.push(&styles[next]);
                next += 1;
            }
            if let Some(l) = in_link {
                push_link_open(&mut out, l);
            }
        }
        if next_link < links.len() && links[next_link].start == i {
            push_link_open(&mut out, &links[next_link]);
            in_link = Some(&links[next_link]);
            next_link += 1;
        }
        push_escaped(&mut out, *c);
        if in_link.is_some_and(|l| l.end == i) {
            out.push_str("</a>");
            in_link = None;
        }
        if open.last().is_some_and(|s| s.end == i) {
            if in_link.is_some() {
                out.push_str("</a>");
            }
            while open.last().is_some_and(|s| s.end == i) {
                out.push_str(tag(open.pop().unwrap().kind, true));
            }
            if let Some(l) = in_link {
                push_link_open(&mut out, l);
            }
        }
    }
    if in_link.is_some() {
        out.push_str("</a>");
    }
    while let Some(s) = open.pop() {
        out.push_str(tag(s.kind, true));
    }
    out.push_str("</span>");
    Some(out)
}

fn tag(kind: Kind, close: bool) -> &'static str {
    match (kind, close) {
        (Kind::Strong, false) => "<b>",
        (Kind::Strong, true) => "</b>",
        (Kind::Emphasis, false) => "<i>",
        (Kind::Emphasis, true) => "</i>",
        (Kind::Strike, false) => "<s>",
        (Kind::Strike, true) => "</s>",
        (Kind::PreformattedSpan | Kind::PreformattedBlock, false) => "<code>",
        (Kind::PreformattedSpan | Kind::PreformattedBlock, true) => "</code>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each style as `kind[text]`, text including the directives (mirrors Android's test).
    fn styles(text: &str) -> Vec<String> {
        let chars: Vec<char> = text.chars().collect();
        parse(text)
            .into_iter()
            .map(|s| {
                let k = match s.kind {
                    Kind::Strong => "*",
                    Kind::Emphasis => "_",
                    Kind::Strike => "~",
                    Kind::PreformattedSpan => "`",
                    Kind::PreformattedBlock => "```",
                };
                let open = if s.closed { "" } else { "(open)" };
                format!("{k}{open}[{}]", chars[s.start..=s.end].iter().collect::<String>())
            })
            .collect()
    }

    fn check(text: &str, expected: &[&str]) {
        assert_eq!(styles(text), expected, "styles of {text:?}");
    }

    #[test]
    fn spec_span_examples() {
        check("plain span", &[]);
        check("*strong span*", &["*[*strong span*]"]);
        check("plain _emphasis_ plain", &["_[_emphasis_]"]);
        check("`pre` plain *strong*", &["`[`pre`]", "*[*strong*]"]);
        check("*strong*plain*", &["*[*strong*]"]);
        check("* plain *strong*", &["*[*strong*]"]);
    }

    #[test]
    fn spec_nothing_styled() {
        for t in ["not strong*", "*not strong", "*not \n strong*", "*not *strong", "**", "***", "****"] {
            check(t, &[]);
        }
    }

    #[test]
    fn span_types_and_nesting() {
        check("Everyone ~dis~likes cake.", &["~[~dis~]"]);
        check("This is `*monospace*`", &["`[`*monospace*`]"]);
        check("This is *`monospace and bold`*", &["*[*`monospace and bold`*]", "`[`monospace and bold`]"]);
        check("*_both_*", &["*[*_both_*]", "_[_both_]"]);
        check("**bold**", &[]);
        check("snake_case_name", &[]);
    }

    #[test]
    fn plain_blocks_are_lines() {
        check("but there is no *formatting\nas spans* may not escape blocks.", &[]);
    }

    #[test]
    fn preformatted_blocks() {
        check("```ignored\n(println)\n```\n\nafter", &["```[```ignored\n(println)\n```]"]);
        check("```\n*not strong*\n```", &["```[```\n*not strong*\n```]"]);
        check("```\ncode\n*still code*", &["```(open)[```\ncode\n*still code*]"]);
        check("```\ncode ```\nmore", &["```(open)[```\ncode ```\nmore]"]);
        check("text ```\ncode", &[]);
        check("*bold*\n```\ncode\n```\n_after_", &["*[*bold*]", "```[```\ncode\n```]", "_[_after_]"]);
    }

    #[test]
    fn quotations() {
        check("> That that *is*, is.\n\nSaid the old hermit", &["*[*is*]"]);
        check(">*strong*", &["*[*strong*]"]);
        check(">> _That_ that\n> Said the *old* hermit\n\nWho?", &["_[_That_]", "*[*old*]"]);
        check(
            "> ```\n> (println)\n\nbut this *line* is plaintext!",
            &["```(open)[```\n> (println)]", "*[*line*]"],
        );
    }

    #[test]
    fn multibyte_text_keeps_char_positions() {
        check("😀 *fett* äöü", &["*[*fett*]"]);
    }

    #[test]
    fn unclosable_openers_stay_linear() {
        let text = "*a _b ~c `d ".repeat(50_000);
        let t = std::time::Instant::now();
        assert!(parse(&text).is_empty());
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }

    #[test]
    fn html_rendering_escapes_everything() {
        assert_eq!(to_html("plain <b>text</b>", true), None);
        assert_eq!(
            to_html("*<script>* & `x`", true),
            Some("<span style=\"white-space: pre-wrap;\"><b>*&lt;script&gt;*</b> &amp; <code>`x`</code></span>".into())
        );
        assert_eq!(
            to_html("*_both_*", true),
            Some("<span style=\"white-space: pre-wrap;\"><b>*<i>_both_</i>*</b></span>".into())
        );
        assert_eq!(
            to_html("> *q*", true),
            Some("<span style=\"white-space: pre-wrap;\">&gt; <b>*q*</b></span>".into())
        );
    }

    fn link_texts(text: &str) -> Vec<(String, String)> {
        let chars: Vec<char> = text.chars().collect();
        find_links(text)
            .into_iter()
            .map(|l| (chars[l.start..=l.end].iter().collect(), l.href))
            .collect()
    }

    #[test]
    fn links_are_detected_and_trimmed() {
        let l = |t: &str, h: &str| (t.to_string(), h.to_string());
        assert_eq!(link_texts("see https://example.org/x?a=1."), [l("https://example.org/x?a=1", "https://example.org/x?a=1")]);
        assert_eq!(link_texts("go to www.monocles.eu!"), [l("www.monocles.eu", "https://www.monocles.eu")]);
        assert_eq!(
            link_texts("(see https://en.wikipedia.org/wiki/A_(b))"),
            [l("https://en.wikipedia.org/wiki/A_(b)", "https://en.wikipedia.org/wiki/A_(b)")]
        );
        assert_eq!(link_texts("join xmpp:room@muc.example?join"), [l("xmpp:room@muc.example?join", "xmpp:room@muc.example?join")]);
        assert_eq!(link_texts("HTTP://EXAMPLE.ORG"), [l("HTTP://EXAMPLE.ORG", "HTTP://EXAMPLE.ORG")]);
        assert_eq!(link_texts("*https://x.org*"), [l("https://x.org", "https://x.org")]);
        for t in ["https://", "www.", "www.nodot", "foohttps://x.org", "user@www.x.org", "plain text"] {
            assert!(find_links(t).is_empty(), "{t:?}");
        }
    }

    #[test]
    fn links_render_escaped_and_nested() {
        assert_eq!(
            to_html("a https://x.org/?q=<b>&r=\"1\"", true),
            Some(
                "<span style=\"white-space: pre-wrap;\">a <a href=\"https://x.org/?q=\">https://x.org/?q=</a>&lt;b&gt;&amp;r=&quot;1&quot;</span>"
                    .into()
            )
        );
        assert_eq!(
            to_html("*https://x.org*", true),
            Some("<span style=\"white-space: pre-wrap;\"><b>*<a href=\"https://x.org\">https://x.org</a>*</b></span>".into())
        );
        assert_eq!(
            to_html("`https://x.org`", true),
            Some("<span style=\"white-space: pre-wrap;\"><code>`https://x.org`</code></span>".into())
        );
        // A styled span right after a link stays outside it.
        assert_eq!(
            to_html("https://x.org/a *b*", true),
            Some("<span style=\"white-space: pre-wrap;\"><a href=\"https://x.org/a\">https://x.org/a</a> <b>*b*</b></span>".into())
        );
        assert_eq!(
            to_html("*bold* https://x.org", false),
            Some("<span style=\"white-space: pre-wrap;\">*bold* <a href=\"https://x.org\">https://x.org</a></span>".into())
        );
        assert_eq!(to_html("no links here", true), None);
    }

    #[test]
    fn many_links_and_code_spans_stay_linear() {
        let text = "`x` https://x.org ".repeat(50_000);
        let t = std::time::Instant::now();
        let html = to_html(&text, true).unwrap();
        assert_eq!(html.matches("<a href=").count(), 50_000);
        assert_eq!(html.matches("<code>").count(), 50_000);
        assert!(t.elapsed() < std::time::Duration::from_secs(2));
    }
}
