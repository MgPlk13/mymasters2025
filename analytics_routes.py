from flask import Blueprint, render_template
from sqlalchemy.orm import Session, joinedload
from analytics_module import engine, AttackLog
from collections import Counter
from datetime import datetime
from decorators import login_required

analytics_bp = Blueprint("analytics", __name__)

@analytics_bp.route("/analytics")
@login_required
def analytics():
    with Session(engine) as db:
        logs = db.query(AttackLog) \
            .options(joinedload(AttackLog.attack_type)) \
            .order_by(AttackLog.timestamp.desc()) \
            .all()

        ai_count_today = 0
        hourly_counter = Counter()
        dangerous_queries = []

        for log in logs:
            try:
                ts = datetime.strptime(log.timestamp, "%Y-%m-%d %H:%M:%S")
                hour = ts.strftime("%H:00")
                hourly_counter[hour] += 1

                if log.reason.startswith("AI") and ts.date() == datetime.today().date():
                    ai_count_today += 1
                    dangerous_queries.append((ts, log.reason, log.query, getattr(log.attack_type, "code", None), log.score))
            except Exception:
                continue

        top_data = sorted(dangerous_queries, key=lambda x: x[0], reverse=True)[:5]

        top_queries = [
            {
                "timestamp": t.strftime("%Y-%m-%d %H:%M:%S"),
                "reason": r,
                "query": q,
                "attack_type": atype or "-",
                "score": f"{s:.2f}" if s is not None else "-"
            }
            for t, r, q, atype, s in top_data
        ]

    return render_template(
        "analytics.html",
        ai_today=ai_count_today,
        hourly_data=sorted(hourly_counter.items()),
        top_queries=top_queries
    )
