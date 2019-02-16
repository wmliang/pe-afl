FROM python:3.7-alpine

LABEL "com.github.actions.name"="Python Syntax Checker"
LABEL "com.github.actions.description"="Run flake8 to find syntax errors in a Python repo."
LABEL "com.github.actions.icon"="upload-cloud"
LABEL "com.github.actions.color"="6f42c1"

RUN pip install --upgrade pip
RUN pip install flake8
RUN python --version ; pip --version ; echo "flake8 $(flake8 --version)" ; echo "===================="

CMD ["flake8", ".", "--count", "--select=E901,E999,F821,F822,F823", "--show-source", "--statistics"]
