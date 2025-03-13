import os, json, re

cargo_meta = json.loads(os.popen("cargo metadata --format-version 1 -q").read())
version: str = next(p["version"] for p in cargo_meta["packages"] if p["name"] == "arxan-disabler")

with open("CHANGELOG.md", "r") as f:
    changelog = f.read()

regex = re.compile(r"\[" + version.replace(".", "\\.") + r"\][^\n]*\n+(.*?)\n\#\# ", re.S)
changes = next(regex.finditer(changelog)).group(1)

print(changes)