import sqlite3
i = "daan"
con=sqlite3.connect("./kakaourl.db")
cursor = con.cursor()
cursor.execute("insert into kakao (kakaourl) values (\'" + i + "\');")
con.commit()
