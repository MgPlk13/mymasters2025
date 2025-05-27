from flask import Flask, request, render_template, jsonify
from transformers import pipeline
from sqlalchemy import text, create_engine
from datetime import datetime
from config_db import DATABASE_URI, SECRET_KEY
from auth_module import auth_bp
from log_module import log_bp
from analytics_routes import analytics_bp
from analytics_module import AttackLog, Session as AnalyticsSession

app = Flask(__name__)
app.secret_key = SECRET_KEY

app.register_blueprint(analytics_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(log_bp)

classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

engine = create_engine(DATABASE_URI)

blocked_keywords = [
    "drop", "truncate", "insert", "update", "delete",
    "alter", "grant", "revoke", "create", "--", "union"
]

def is_query_safe_by_rules(sql: str):
    sql = sql.lower()
    return not any(keyword in sql for keyword in blocked_keywords)

def log_blocked_query(reason: str, sql: str, score=None, source_ip="127.0.0.1"):
    with AnalyticsSession() as db:
        attack = AttackLog(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            reason=reason,
            query=sql.strip(),
            score=score,
            source_ip=source_ip,
            status="blocked"
        )
        db.add(attack)
        db.commit()
        print(f"✅ Заблокований запит записано: {sql.strip()}")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check_query", methods=["POST"])
def check_sql_query():
    data = request.get_json()
    sql = data.get("query", "").strip()

    if not sql:
        return jsonify({"error": "Запит порожній"}), 400

    if not is_query_safe_by_rules(sql):
        log_blocked_query("RULE", sql)
        return jsonify({
            "query": sql,
            "result": "❌ Заборонена SQL-інструкція"
        })

    result = classifier(sql)[0]
    label = result["label"]
    score = result["score"]

    if label == "NEGATIVE":
        log_blocked_query("AI", sql, score)
        return jsonify({
            "query": sql,
            "score": f"{score:.2f}",
            "result": "❌ Підозрілий SQL-запит (AI)"
        })

    try:
        with engine.connect() as conn:
            result = conn.execute(text(sql))
            rows = [dict(row) for row in result]
        return jsonify({
            "query": sql,
            "score": f"{score:.2f}",
            "result": "✅ Запит виконано",
            "rows": rows
        })
    except Exception as e:
        return jsonify({
            "error": "❌ Помилка виконання SQL",
            "details": str(e)
        })

if __name__ == "__main__":
    app.run(debug=True)
