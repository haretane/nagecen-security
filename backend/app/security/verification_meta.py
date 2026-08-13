from html.parser import HTMLParser


VERIFICATION_META_NAME = "nagecen-site-verification"


class VerificationMetaParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_head = False
        self.head_finished = False
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        normalized_tag = tag.lower()
        if normalized_tag == "head" and not self.head_finished:
            self.in_head = True
            return

        if normalized_tag == "body":
            self.in_head = False
            self.head_finished = True
            return

        if normalized_tag != "meta" or not self.in_head:
            return

        attributes = {
            name.lower(): value for name, value in attrs if value is not None
        }
        if attributes.get("name", "").lower() == VERIFICATION_META_NAME:
            self.values.append(attributes.get("content", ""))

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "head":
            self.in_head = False
            self.head_finished = True


def contains_verification_meta(html: str, expected_token: str) -> bool:
    parser = VerificationMetaParser()
    parser.feed(html)
    return expected_token in parser.values
