from logsentinel.cli import main


def test_simulate_and_analyze_html(tmp_path, capsys):
    assert main(["simulate", "--out", str(tmp_path)]) == 0
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    code = main(["--no-color", "analyze", str(tmp_path / "auth.log"), str(tmp_path / "access.log"), "--html", str(html), "--json", str(js)])
    assert code == 0
    page = html.read_text()
    assert "<svg" in page and "Successful login after brute force" in page and "<script" not in page.split("<pre>")[0]
    assert "203.0.113.45" in capsys.readouterr().out


def test_payloads_are_escaped_in_html(tmp_path):
    log = tmp_path / "access.log"
    log.write_text('192.0.2.5 - - [01/Oct/2026:10:00:00 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 403 10 "-" "x"\n')
    html = tmp_path / "r.html"
    main(["--no-color", "analyze", str(log), "--html", str(html)])
    page = html.read_text()
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_fail_on(tmp_path):
    main(["simulate", "--out", str(tmp_path)])
    assert main(["--no-color", "analyze", str(tmp_path / "auth.log"), "--fail-on", "critical"]) == 1


def test_llm_flag_without_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    main(["simulate", "--out", str(tmp_path)])
    main(["--no-color", "analyze", str(tmp_path / "auth.log"), "--llm", "--json", "-"])
    assert "LLM summary skipped" in capsys.readouterr().out
