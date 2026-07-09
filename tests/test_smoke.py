def test_version_is_a_string():
    import asi_scan
    assert isinstance(asi_scan.__version__, str)
    assert asi_scan.__version__
