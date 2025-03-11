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
