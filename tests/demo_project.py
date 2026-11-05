"""Builds an intentionally vulnerable demo project in a directory.
Fake secrets are assembled at runtime so no secret-shaped strings are committed
(keeps GitHub push protection and secret scanners quiet)."""
from pathlib import Path


def build(root):
    root = Path(root)
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "android").mkdir(exist_ok=True)
    stripe = "sk_" + "live_" + "51HxyzABCDEFGHIJKLMNOPqr"
    openai = "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH"
    dburl = "postgres://" + "admin:Sup3rS3cretPw" + "@db.prod.internal:5432/app"
    (root / "src/app.py").write_text(f'''import os, hashlib, subprocess, pickle, yaml
from flask import Flask, request, render_template_string, send_file, redirect
import sqlite3, jwt
app = Flask(__name__)
DEBUG = True
STRIPE_KEY = "{stripe}"
JWT_SECRET = "secret"
DB = "{dburl}"
OK = os.environ["SAFE_KEY"]
api_key = "your_api_key_here"

@app.route("/user")
def user():
    uid = request.args["id"]
    cur = sqlite3.connect("a.db").cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {{uid}}")
    return str(cur.fetchall())

@app.route("/ping")
def ping():
    subprocess.run("ping -c 1 " + request.args["h"], shell=True)

@app.route("/hi")
def hi():
    return render_template_string("Hello " + request.args["n"])

@app.route("/dl")
def dl():
    return send_file(request.args["f"])

@app.route("/go")
def go():
    return redirect(request.args["next"])

@app.route("/login", methods=["POST"])
def login():
    pw = hashlib.md5(request.form["pw"].encode()).hexdigest()
    print("login", request.form["password"])
    return pw

def load(b):
    return pickle.loads(b), yaml.load(b)

def tok(t):
    return jwt.decode(t, options={{"verify_signature": False}})
''')
    (root / "src/server.js").write_text('''const express = require("express"); const cors = require("cors");
const app = express(); app.use(cors());
app.get("/doc/:id", async (req, res) => { const d = await Doc.findById(req.params.id); res.json(d); });
app.post("/u", async (req, res) => { await User.create(req.body); res.end(); });
app.get("/q", (req, res) => { db.query(`SELECT * FROM t WHERE n = '${req.query.n}'`); });
app.get("/x", (req, res) => { exec(`ls ${req.query.d}`); });
app.get("/f", async (req,res)=>{ const r = await fetch(req.query.url); res.send(await r.text()); });
el.innerHTML = userInput;
localStorage.setItem("token", t);
const c = { secure: false, httpOnly: false };
const k = process.env.NEXT_PUBLIC_OPENAI_KEY;
const safe = process.env.API_KEY;
''')
    (root / "src/App.jsx").write_text('''import AsyncStorage from "@react-native-async-storage/async-storage";
export default function A({html}) { AsyncStorage.setItem("authToken", "x"); return <div dangerouslySetInnerHTML={{__html: html}} />; }
''')
    (root / ".env").write_text(f"OPENAI={openai}\nDB=x\n")
    (root / ".env.example").write_text("API_KEY=your_key_here\n")
    (root / "Dockerfile").write_text('FROM node:latest\nRUN curl https://x.sh | sh\nCMD ["node","a.js"]\n')
    (root / "firestore.rules").write_text('service cloud.firestore { match /{d=**} { allow read, write: if true; } }\n')
    (root / "android/AndroidManifest.xml").write_text('<application android:usesCleartextTraffic="true"/>\n')
    (root / "tests/test_a.py").write_text(f'x = "{stripe}"\n')
    (root / "package.json").write_text('{"name":"demo","dependencies":{"express":"4"}}\n')
    return root


if __name__ == "__main__":
    import sys
    build(sys.argv[1] if len(sys.argv) > 1 else "demo-vulnerable")
