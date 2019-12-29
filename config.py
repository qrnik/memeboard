import os

from flask import Flask


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY')
    GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI')
    FLASK_ADMIN_SWATCH = 'superhero'


class DevelopmentConfig(Config):
    pass


class ProductionConfig(Config):
    pass


class TestConfig(Config):
    SECRET_KEY = 'secret'
    GOOGLE_CLIENT_ID = 'id'
    GOOGLE_CLIENT_SECRET = 'secret'
    SQLALCHEMY_DATABASE_URI = 'sqlite://'


def configure(app: Flask):
    if app.env == 'production':
        config = ProductionConfig
    elif app.env == 'test':
        config = TestConfig
    elif app.env == 'development':
        config = DevelopmentConfig
    else:
        raise ValueError(f"Unknown Flask environment: {app.env}")
    app.config.from_object(config)
