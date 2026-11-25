1) افتح bot.py وعدّل سطرين فقط في الأعلى:
   BOT_TOKEN = "..."   و   OWNER_ID = ...
2) ارفع المجلد كله (bot.py + Dockerfile + requirements.txt) على GitHub (مستودع Private)
3) اربطه بالاستضافة واختر النشر بـ Dockerfile
4) خذ الرابط الذي تعطيه الاستضافة، وإن لم يُكتشف تلقائياً ضعه في BASE_URL داخل bot.py (أو كمتغير BASE_URL)
