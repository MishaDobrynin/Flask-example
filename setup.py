from setuptools import find_packages, setup

setup(
    name='flask_example',
    version='1.0.0',
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    install_requires=[
        "WTForms",
        "SQLAlchemy",
        "Flask",
        "Flask-WTF",
        "Flask-SQLAlchemy",
        "Flask-Login",
        "Flask-Bcrypt",
        "first",
        "bcrypt"
    ],
)