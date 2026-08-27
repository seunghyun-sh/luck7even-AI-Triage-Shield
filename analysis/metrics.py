import json
import os

def calculate_metrics(results_file, ground_truth_file):
    try:
        with open(results_file, 'r', encoding='utf-8') as f:
            results_env = json.load(f)
        with open(ground_truth_file, 'r', encoding='utf-8') as f:
            truth_env = json.load(f)
    except FileNotFoundError as e:
        print(f"데이터 파일을 찾을 수 없습니다: {e}")
        return

    # 정답표(Ground Truth)를 case_id 기준으로 딕셔너리로 변환
    truth_map = {case["case_id"]: case["label"] for case in truth_env.get("cases", [])}

    TP = TN = FP = FN = 0
    excluded_count = 0

    print("AI 성능 평가 지표 계산 중...\n")

    for finding in results_env.get("findings", []):
        case_id = finding.get("case_id")
        
        # 1. 정답표에 없는 케이스는 제외
        if case_id not in truth_map:
            continue
            
        true_label = truth_map[case_id]
        ai_data = finding.get("ai", {})
        ai_status = ai_data.get("status")
        ai_label = ai_data.get("label")

        # 2. 계약서 6.3 규칙: INCONCLUSIVE, NOT_REQUESTED, FAILED는 평가에서 제외
        if ai_status != "COMPLETED" or ai_label not in ["VULNERABLE", "SAFE"]:
            excluded_count += 1
            continue

        # 3. 혼동 행렬(Confusion Matrix) 계산
        if true_label == "VULNERABLE" and ai_label == "VULNERABLE":
            TP += 1  # 정탐 (진짜 공격을 찾아냄)
        elif true_label == "SAFE" and ai_label == "SAFE":
            TN += 1  # 정상 (안전한 걸 안전하다고 함)
        elif true_label == "SAFE" and ai_label == "VULNERABLE":
            FP += 1  # 오탐 (안전한 걸 공격이라고 오해함)
        elif true_label == "VULNERABLE" and ai_label == "SAFE":
            FN += 1  # 미탐 (진짜 공격을 놓침 - 가장 위험함!)

    # 4. 성능 지표 공식 계산
    total_scored = TP + TN + FP + FN
    
    accuracy = (TP + TN) / total_scored if total_scored > 0 else 0
    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall = TP / (TP + FN) if (TP + FN) > 0 else 0

    print(f"정답표 데이터: 총 {len(truth_map)}건 중 {total_scored}건 평가 완료 (제외: {excluded_count}건)")
    print("-" * 40)
    print(f"정확도 (Accuracy):  {accuracy * 100:.2f}% (전체 중 AI가 맞춘 비율)")
    print(f"정밀도 (Precision): {precision * 100:.2f}% (AI가 공격이라 한 것 중 진짜 공격의 비율)")
    print(f"재현율 (Recall):    {recall * 100:.2f}% (실제 공격 중 AI가 놓치지 않고 찾아낸 비율)")
    print("-" * 40)
    print(f"세부 지표: [TP(정탐): {TP}, TN(정상): {TN}, FP(오탐): {FP}, FN(미탐): {FN}]")

if __name__ == "__main__":
    # 테스트 구동: 경로를 실제 경로에 맞게 지정해 주세요.
    run_id = "run-xss-20260827-103719"
    processed_json = os.path.join("data", "processed", run_id, "results.json")
    # 실제 정답표 파일 경로를 입력 (현재는 예시)
    truth_json = os.path.join("configs", "ground-truth.example.json") 
    
    calculate_metrics(processed_json, truth_json)