import click
from flask.cli import with_appcontext
from .utils.db import init_db

def init_app(app):
    """Register CLI commands with the app"""
    app.cli.add_command(init_db_command)

@click.command('init-db')
@with_appcontext
def init_db_command():
    """Initialize the database."""
    init_db()
    click.echo('Initialized the database.')