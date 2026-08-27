import os
import pandas as pd
import json
from dotenv import load_dotenv
from openai import OpenAI

# 파일들에서 필요한 내용을 불러오기
from analysis.models import TriageResult
from analysis.prompts import get_triage_prompt

# 1. API 키 로드
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def analyze_vulnerability(row):
    """단일 로그(행)를 AI에게 분석시키는 함수"""
    # prompts.py에서 프롬프트를 가져옴
    prompt = get_triage_prompt(row['url'], row['parameter'], row['payload'], row['response_body'])
    
    # Structured Outputs 기능 적용
    response = client.beta.chat.completions.parse(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "보안 취약점 진단 도우미입니다."},
            {"role": "user", "content": prompt}
        ],
        response_format=TriageResult, # models.py에서 가져온 클래스 적용
        temperature=0
    )
    
    result_dict = json.loads(response.choices[0].message.content)
    result_dict.update({
        "finding_id": row.get('finding_id', 'N/A'),
        "vuln_type": row.get('vuln_type', 'N/A'),
        "url": row['url'],
        "parameter": row['parameter'],
        "payload": row['payload']
    })
    return result_dict

def main():
    print("1차 탐지 데이터 분석 시작...")
    
    try:
        df = pd.read_csv('test_raw_findings.csv', encoding='utf-8-sig', sep=',')
    except FileNotFoundError:
        print("CSV 파일이 없습니다. 최상위 폴더에 'test_raw_findings.csv'를 넣어주세요.")
        return

    final_results = []
    
    for index, row in df.iterrows():
        print(f"분석 중: {row.get('finding_id', 'Unknown')}...")
        analyzed_data = analyze_vulnerability(row)
        final_results.append(analyzed_data)
        
    with open('triaged_results_sample.json', 'w', encoding='utf-8') as f:
        json.dump(final_results, f, ensure_ascii=False, indent=2)
        
    print("분석 완료! 모듈화가 성공적으로 적용되었습니다.")

if __name__ == "__main__":
    main()