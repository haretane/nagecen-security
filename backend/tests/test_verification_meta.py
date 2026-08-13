from app.security.verification_meta import contains_verification_meta


TOKEN = "test-verification-token"


def test_finds_verification_meta_inside_head() -> None:
    html = f"""
    <!doctype html>
    <html>
      <head>
        <meta name="nagecen-site-verification" content="{TOKEN}">
      </head>
      <body></body>
    </html>
    """

    assert contains_verification_meta(html, TOKEN)


def test_ignores_verification_meta_inside_body() -> None:
    html = f"""
    <html>
      <head><title>Example</title></head>
      <body>
        <meta name="nagecen-site-verification" content="{TOKEN}">
      </body>
    </html>
    """

    assert not contains_verification_meta(html, TOKEN)


def test_rejects_wrong_token() -> None:
    html = """
    <html>
      <head>
        <meta name="nagecen-site-verification" content="different-token">
      </head>
    </html>
    """

    assert not contains_verification_meta(html, TOKEN)
