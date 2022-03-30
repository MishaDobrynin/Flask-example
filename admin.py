import sqlite3
from flask import Blueprint, render_template, url_for, redirect, session, request, flash, g

admin = Blueprint('admin', __name__, template_folder='templates', static_folder='static')