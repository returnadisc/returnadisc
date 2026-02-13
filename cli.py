"""CLI-kommandon för ReturnaDisc."""
import click
from flask.cli import with_appcontext

from database import db


def register_commands(app):
    """Registrera alla CLI-kommandon."""
    
    @app.cli.command('init-db')
    @with_appcontext
    def init_db_command():
        """Initiera databasen."""
        db.init_tables()
        click.echo('Database initialized.')

    @app.cli.command('reset-db')
    @click.confirmation_option(prompt='Are you sure? This will delete all data!')
    @with_appcontext
    def reset_db_command():
        """Nollställ databasen."""
        db.reset_database(confirm=True)
        click.echo('Database reset.')

    @app.cli.command('create-admin')
    @click.option('--email', prompt=True)
    @click.password_option()
    @with_appcontext
    def create_admin_command(email, password):
        """Skapa admin-användare."""
        from werkzeug.security import generate_password_hash
        hash_value = generate_password_hash(password)
        click.echo(f'Admin password hash: {hash_value}')
        click.echo('Add this to your environment as ADMIN_PASSWORD_HASH')