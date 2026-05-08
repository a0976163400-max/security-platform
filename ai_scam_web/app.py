from flask import Flask, request, render_template
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)

texts = [
    "今天一起吃飯嗎","我晚點回你","明天開會","你到家了嗎","這筆款項已收到",
    "請問商品還在嗎","我等等打給你","明天方便面交嗎",
    "你的帳戶異常請點連結驗證","限時通知帳戶凍結","請先轉帳保證金",
    "急需用錢幫我匯款","投資穩賺不賠","包裹卡關請付款",
    "請提供驗證碼","不要告訴別人","先匯款才可以解鎖帳戶"
]

labels = [0,0,0,0,0,0,0,0, 1,1,1,1,1,1,1,1,1]

vectorizer = TfidfVectorizer()
X = vectorizer.fit_transform(texts)

model = LogisticRegression()
model.fit(X, labels)

risk_words = [
    "轉帳","匯款","保證金","帳戶異常","凍結","點連結",
    "驗證碼","限時","投資","穩賺不賠","付款","解鎖","不要告訴別人"
]

@app.route("/", methods=["GET", "POST"])
def home():
    results = []
    total_high = 0
    all_keywords = set()
    summary = None

    if request.method == "POST":
        message = request.form["message"]
        lines = [line.strip() for line in message.splitlines() if line.strip()]

        for line in lines:
            X_test = vectorizer.transform([line])
            prob = model.predict_proba(X_test)[0][1]
            score = int(prob * 100)
            found = [w for w in risk_words if w in line]

            if score >= 50 or found:
                level = "⚠️ 高風險"
            elif score >= 35:
                level = "🟡 中風險"
            else:
                level = "✅ 低風險"

            results.append({
                "text": line,
                "score": score,
                "level": level,
                "keywords": "、".join(found) if found else "無"
            })

            if level == "⚠️ 高風險":
                total_high += 1

            for k in found:
                all_keywords.add(k)

        if results:
            if total_high >= 2:
                overall = "⚠️ 高風險"
            elif total_high == 1:
                overall = "🟡 中風險"
            else:
                overall = "✅ 低風險"

            summary = {
                "overall": overall,
                "count": total_high,
                "keywords": "、".join(all_keywords) if all_keywords else "無"
            }

    return render_template("index.html", results=results, summary=summary)

if __name__ == "__main__":
    app.run(debug=True)