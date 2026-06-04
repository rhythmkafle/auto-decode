# Wazuh Decoder Builder

Small browser app that turns a sample log line into a starter Wazuh decoder.

## Run

Open [index.html](/home/buddha404/Desktop/decoder/index.html) directly in a browser, or serve the folder locally:

```bash
python3 -m http.server 8000
```

Then open `http://localhost:8000`.

## What it does

- Detects common syslog-style headers and maps them to `<program_name>`.
- Detects JSON logs and generates a decoder that uses `JSON_Decoder`.
- Generates a PCRE2 `<regex>` and `<order>` list for plain-text logs.
- Lets you rename detected fields before copying the XML.

## Output

Copy the generated XML into:

```text
/var/ossec/etc/decoders/local_decoder.xml
```

Test it on your Wazuh manager with:

```bash
/var/ossec/bin/wazuh-logtest
```

This generator is intentionally conservative. Review the regex and field names before using it in production.
