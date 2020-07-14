import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

from collections import namedtuple

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

    portfolio = get_portfolio(session["user_id"])
    cash = float(get_available_cash(session["user_id"]))
    grand_total = sum([entry.total for entry in portfolio]) + cash

    return render_template("index.html", portfolio=portfolio, cash = cash, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return redirect("/buy")
        else:
            symbol = request.form.get("symbol")
        # Ensure quantity was submitted
        if not request.form.get("shares"):
            return redirect("/buy")
        else:
            shares = int(request.form.get("shares"))

        # query quote
        response = lookup(symbol)
        if not response:
            return apology("Ticker symbol does not exist", 403)
        else:
            price = float(response["price"])
            name = response["name"]

        # calculate total price
        total = shares * price
        # get available cash
        available = get_available_cash(session["user_id"])
        # check if user has enough cash
        if available < total:
            return apology("Sorry, not enough cash to purchase shares...", 403)

        # update database
        record_purchase(session["user_id"], symbol, name, price, shares)
        # flash message
        flash('Bought!')

        # return to index page
        return redirect("/")

    else:

        # GET method: show the buy form
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    entries = get_history(session["user_id"])
    return render_template("history.html", entries=entries)


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
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

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
    if request.method == 'POST':

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return redirect("/quote")
        else:
            symbol = request.form.get("symbol")

        # query quote
        response = lookup(symbol)
        if not response:
            return apology("symbol symbol does not exist", 403)

        # display results
        return render_template("quote_result.html", name=response["name"], symbol=response["symbol"], price=usd(response["price"]))

    else:

        # GET method: show the quote query form
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        else:
            username = request.form.get("username")
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)
        else:
            password = request.form.get("password")
        # Ensure pwd confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm password", 403)
        else:
            confirmation = request.form.get("confirmation")
        # Ensure password == confirmation
        if password != confirmation:
            return apology("passwords do not match", 403)

        # Hash password
        password_hash = generate_password_hash(password)

        # Insert user to database
        if not user_exists(username):
            insert_new_user(username, password_hash)
        else:
            return apology("user already exists", 403)

        # Redirect user to home page
        return redirect("/")

    else:

        # GET method: show the registration form
        return render_template("register.html")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    """Change user password"""
    if request.method == 'POST':

        # Get user ID
        user_id = session["user_id"]

        # Ensure current password was submitted
        if not request.form.get("current_password"):
            return apology("must provide current password", 403)
        else:
            current_password = request.form.get("current_password")
        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return apology("must provide new password", 403)
        else:
            new_password = request.form.get("new_password")
        # Ensure pwd confirmation was submitted
        if not request.form.get("confirmation"):
            return apology("must confirm password", 403)
        else:
            confirmation = request.form.get("confirmation")

        # Check current password
        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=user_id)
        if not check_password_hash(rows[0]["hash"], current_password):
            return apology("invalid password", 403)
        # Ensure new password == confirmation
        if new_password != confirmation:
            return apology("passwords do not match", 403)

        # Hash password
        password_hash = generate_password_hash(new_password)

        # Update password in database
        update_password(user_id, password_hash)
        flash("Password updated!")

        # Redirect user to home page
        return redirect("/")

    else:

        # GET method: show the registration form
        return render_template("change_password.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':

        # Ensure symbol was submitted
        if not request.form.get("symbol"):
            return redirect("/sell")
        else:
            symbol = request.form.get("symbol")
        # Ensure quantity was submitted
        if not request.form.get("shares"):
            return redirect("/sell")
        else:
            shares = int(request.form.get("shares"))

        # query quote
        response = lookup(symbol)
        if not response:
            return apology("Ticker symbol does not exist", 403)
        else:
            price = float(response["price"])
            name = response["name"]

        # get available shares
        shares_owned = get_shares(session["user_id"], symbol)
        # check if user has enough shares
        if shares_owned < shares:
            return apology("Sorry, you do not own that many shares of the stock...", 403)

        # calculate total price
        total = shares * price

        # update database
        record_sale(session["user_id"], symbol, name, price, shares)
        # flash message
        flash('Sold!')

        # return to index page
        return redirect("/")

    else:

        # GET method: show the sell form

        # get list of shares in stock
        symbols = get_list_of_shares(session["user_id"])
        # render page
        return render_template("sell.html", symbols=symbols)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

def insert_new_user(username, password_hash):
    """
    Inserts a new user into the database.

    @param username         username
    @param password_hash    password hash string
    """
    db.execute(
        "INSERT INTO users (username, hash) VALUES (:username, :password_hash);",
        username=username,
        password_hash=password_hash
    )


def user_exists(username):
    """
    Checks if a username exists in the database.

    @param username     username to check
    @return             True is exists
    """
    rows = db.execute("SELECT * FROM users WHERE username = :username;", username=username)
    return (len(rows) > 0)


def update_password(user_id, password_hash):
    """
    Inserts a new user into the database.

    @param user_id          user ID (primary key)
    @param password_hash    password hash string
    """
    db.execute(
        "UPDATE users SET hash = :password_hash WHERE id = :user_id;",
        password_hash=password_hash,
        user_id=user_id,
    )


def get_available_cash(user_id):
    """
    Returns user's available cash amount.

    @param user_id      user ID (primary key)
    @return             amount of cash available
    """
    rows = db.execute("SELECT * FROM users WHERE id = :user_id;", user_id=user_id)
    return rows[0]["cash"]


def get_shares(user_id, symbol):
    """
    Returns user's available share quantity.

    @param user_id      user ID (primary key)
    @param symbol       ticker symbol of share to check
    @return             quantity of shares in stock
    """

    # get number of shares
    rows = db.execute(
        """
        SELECT sum(quantity) AS shares
        FROM transactions
        WHERE (user_id = :user_id AND symbol = :symbol)
        GROUP BY symbol;
        """,
        user_id=user_id,
        symbol=symbol
    )
    if len(rows) == 1:
        return rows[0]["shares"]
    else:
        return 0


def record_purchase(user_id, symbol, name, price, shares):
    """
    Records a purchase transaction into the database.

    @param user_id      user ID (primary key)
    @param symbol       ticker symbol of share to purchase
    @param name         name of share to purchase
    @param price        purchase price per share
    @param shares       quantity of shares to purchase
    """

    # record transaction
    db.execute(
        "INSERT INTO transactions(user_id, symbol, name, quantity, price) VALUES (:user_id, :symbol, :name, :shares, :price);",
        user_id=user_id,
        symbol=symbol,
        name=name,
        price=price,
        shares=shares
    )

    # decrease cash
    current_balance = get_available_cash(user_id)
    new_balance = current_balance - price * shares
    db.execute(
        "UPDATE users SET cash = :new_balance WHERE id = :user_id;",
        new_balance=new_balance,
        user_id=user_id,
    )


def record_sale(user_id, symbol, name, price, shares):
    """
    Records a sale transaction into the database.

    @param user_id      user ID (primary key)
    @param symbol       ticker symbol of share to sell
    @param name         name of share to sell
    @param price        sale price per share
    @param shares       quantity of shares to sell
    """

    # record transaction
    db.execute(
        "INSERT INTO transactions(user_id, symbol, name, quantity, price) VALUES (:user_id, :symbol, :name, :shares, :price);",
        user_id=user_id,
        symbol=symbol,
        name=name,
        price=price,
        shares=-shares
    )

    # increase cash
    current_balance = get_available_cash(user_id)
    new_balance = current_balance + price * shares
    db.execute(
        "UPDATE users SET cash = :new_balance WHERE id = :user_id;",
        new_balance=new_balance,
        user_id=user_id,
    )


def get_list_of_shares(user_id):
    """
    Returns list of shares owned by a user.

    @param user_id      user ID
    @return             list of share symbols
    """

    rows = db.execute(
        """
        SELECT symbol
        FROM transactions
        WHERE user_id = :user_id
        GROUP BY symbol
        HAVING sum(quantity)>0
        ORDER BY symbol;
        """,
        user_id=user_id
    )
    return [row['symbol'] for row in rows]


def get_portfolio(user_id):
    """
    Returns portfolio of a user.

    @param user_id      user ID
    @return             list of named tuples (symbol, name, shares, price, total)  -  excludes free cash
    """

    # define structure
    portfolio = []
    Entry = namedtuple('Entry', 'symbol name shares price total')

    # get shares
    rows = db.execute(
        """
        SELECT symbol, name, sum(quantity) AS shares
        FROM transactions
        WHERE user_id = :user_id
        GROUP BY symbol
        ORDER BY symbol ASC;
        """,
        user_id=user_id
    )

    # add share data to list
    for row in rows:
        symbol = row['symbol']
        name = row['name']
        shares = int(row['shares'])
        price = float(lookup(symbol)['price'])
        total = float(shares * price)
        e = Entry(symbol=symbol, name=name, shares=shares, price=price, total=total)
        portfolio.append(e)

    return portfolio


def get_history(user_id):
    """
    Returns history of transactions of a user.

    @param user_id      user ID
    @return             list of named tuples (symbol, shares, price, timestamp)
    """

    # define structure
    entries = []
    Entry = namedtuple('Entry', 'symbol shares price timestamp')

    # get shares
    rows = db.execute(
        """
        SELECT *
        FROM transactions
        WHERE user_id = :user_id
        ORDER BY trans_time ASC;
        """,
        user_id=user_id
    )

    # add share data to list
    for row in rows:
        symbol = row['symbol']
        shares = int(row['quantity'])
        price = float(row['price'])
        timestamp = row['trans_time']
        e = Entry(symbol=symbol,shares=shares, price=price, timestamp=timestamp)
        entries.append(e)

    return entries


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
