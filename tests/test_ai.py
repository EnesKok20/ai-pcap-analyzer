"""analyze_with_ai icin, gercek Anthropic API'sine gitmeden sahte (mock)
bir istemci ile calisan testler."""

import anthropic

from main import analyze_with_ai


class _SahteMetinBlogu:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _SahteYanit:
    def __init__(self, text, stop_reason="end_turn"):
        self.content = [_SahteMetinBlogu(text)]
        self.stop_reason = stop_reason


class _SahteMessages:
    def __init__(self, yanit, cagri_gecmisi):
        self._yanit = yanit
        self._cagri_gecmisi = cagri_gecmisi

    def create(self, **kwargs):
        self._cagri_gecmisi.append(kwargs)
        return self._yanit


class _SahteAnthropicClient:
    yanit = _SahteYanit("Supheli bir durum tespit edilmedi.")
    cagri_gecmisi = []

    def __init__(self, *args, **kwargs):
        self.messages = _SahteMessages(self.yanit, self.cagri_gecmisi)


def test_analyze_with_ai_yaniti_yazdirir(monkeypatch, capsys):
    monkeypatch.setattr(anthropic, "Anthropic", _SahteAnthropicClient)

    analyze_with_ai(["[1] TCP 1.1.1.1:1 -> 2.2.2.2:2"], stats_text="")

    output = capsys.readouterr().out
    assert "Supheli bir durum tespit edilmedi." in output


def test_analyze_with_ai_reddi_isliyor(monkeypatch, capsys):
    class _ReddedenClient(_SahteAnthropicClient):
        yanit = _SahteYanit("", stop_reason="refusal")

    monkeypatch.setattr(anthropic, "Anthropic", _ReddedenClient)

    analyze_with_ai(["[1] TCP 1.1.1.1:1 -> 2.2.2.2:2"], stats_text="")

    output = capsys.readouterr().out
    assert "reddetti" in output


def test_analyze_with_ai_stats_text_ile_birlikte_gonderiyor(monkeypatch):
    class _KaydedenClient(_SahteAnthropicClient):
        cagri_gecmisi = []

    monkeypatch.setattr(anthropic, "Anthropic", _KaydedenClient)

    analyze_with_ai(["[1] TCP 1.1.1.1:1 -> 2.2.2.2:2"], stats_text="===== Trafik Ozeti =====")

    assert len(_KaydedenClient.cagri_gecmisi) == 1
    gonderilen_mesaj = _KaydedenClient.cagri_gecmisi[0]["messages"][0]["content"]
    assert "Trafik Ozeti" in gonderilen_mesaj
    assert "1.1.1.1:1" in gonderilen_mesaj
