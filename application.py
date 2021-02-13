import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Retrieve portfolio
    portfolio = db.execute("SELECT * FROM portfolio WHERE user_id = ?", session["user_id"])

    # Retrieve cash
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    # Total value of portfolio
    total = cash

    # Lookup name and value of each holding in portfolio
    if len(portfolio) > 0:
        for row in portfolio:
            quote = lookup(row["symbol"])
            row["price"] = quote["price"]
            row["name"] = quote["name"]
            row["total"] = quote["price"] * row["shares"]
            total += row["total"]

    return render_template("index.html", portfolio=portfolio, cash=cash, usd=usd, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)

        # Check if inputs are valid
        if not quote:
            return apology("symbol does not exist :-(")
        if not shares:
            return apology("missing number of shares")
        elif not shares.isdigit():
            return apology("shares should be a positive integer")
        elif int(shares) < 1:
            return apology("shares should be a positive integer")

        shares = int(shares)
        # Get user's current balance
        rows = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        current_balance = rows[0]["cash"]

        # Get total buy price
        buy_price = quote["price"] * shares

        new_balance = current_balance - buy_price

        if new_balance < 0:
            return apology("insufficient balance :(")

        # Update user's cash in users db
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"])

        # Add transaction to transactions db
        db.execute("INSERT INTO transactions (user_id, transaction_type, symbol, shares, price, timestamp) " \
            "VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], "BUY", quote["symbol"], shares, quote["price"], datetime.now())

        # Update portfolio db
        current_holding = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", \
            session["user_id"], quote["symbol"])

        # Add new symbol to portfolio if never user never bought this stock before
        if len(current_holding) != 1:
            db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES (?, ?, ?)", \
                session["user_id"], quote["symbol"], shares)
        else:
            # Update current holding
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?", \
                shares + current_holding[0]["shares"], session["user_id"], quote["symbol"])

        msg = "Bought {} shares of {} for {}.".format(shares, quote["symbol"], usd(quote["price"]))
        flash(msg)
        return redirect("/")

    else:
        return render_template("buy.html")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    # Retrieve all transactions for user
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])

    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        # Lookup symbol
        symbol = request.form.get("symbol")
        quote = lookup(symbol)

        if not quote:
            return apology("could not find quote")

        price = usd(quote["price"])
        return render_template("quoted.html", quote=quote, usd=usd)

    else:
        return render_template("quote.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Ensure valid username
        usernames_list = db.execute("SELECT username FROM users")
        usernames = [username["username"] for username in usernames_list]

        if not request.form.get("username"):
            return apology("must provide username")
        elif request.form.get("username") in usernames:
            return apology("username already exists")

        # Ensure valid password
        elif not request.form.get("password") or not request.form.get("confirmation"):
            return apology("must enter password")
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match")

        # Insert entry into db
        pw_hash = generate_password_hash(request.form.get("password"))
        id = db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", request.form.get("username"), pw_hash)

        # Remember which user has logged in
        session["user_id"] = id

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Error checks
        if symbol == "" or symbol == None:
            return apology("missing symbol")
        if shares == "" or shares == None:
            return apology("missing shares")
        elif int(shares) <= 0:
            return apology("number of shares must be positive")

        # Lookup current price of share
        quote = lookup(symbol)

        if not quote:
            return apology("could not find quote")

        # Get currently owned number of shares
        portfolio_row = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", session["user_id"], quote["symbol"])

        if len(portfolio_row) != 1:
            return apology("you don't own that stock")

        current_shares = portfolio_row[0]["shares"]
        shares_to_sell = int(shares)
        new_shares = current_shares - shares_to_sell

        if new_shares < 0:
            return apology("you tried to sell too many shares")

        # Update transactions db
        db.execute("INSERT INTO transactions (user_id, transaction_type, symbol, shares, price, timestamp) " \
            "VALUES (?, ?, ?, ?, ?, ?)", session["user_id"], "SELL", quote["symbol"], shares_to_sell, quote["price"], datetime.now())

        # Get current cash
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        # Update user's cash in users db
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + shares_to_sell * quote["price"], session["user_id"])

        # Delete current holding if selling all shares
        if new_shares == 0:
            db.execute("DELETE from portfolio WHERE symbol = ? AND user_id = ?", quote["symbol"], session["user_id"])
        else:
            # Else reduce the number of shares
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?", \
                new_shares, session["user_id"], quote["symbol"])

        msg = "Sold {} shares of {} for {}".format(shares, quote["symbol"], usd(quote["price"]))
        flash(msg)
        return redirect("/")
    else:
        # Get user's portfolio
        portfolio =  db.execute("SELECT * FROM portfolio WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", portfolio=portfolio)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
