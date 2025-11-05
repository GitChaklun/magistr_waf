FROM python:3.11-slim

# базовые утилиты
RUN apt-get update && apt-get install -y curl jq bash git build-essential --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attacker

# копируем все скрипты (generate_requests.py, access2features.py, train_isolationforest.py, scripts/)
COPY generate_requests.py /opt/attacker/generate_requests.py
COPY access2features_v2.py /opt/attacker/access2features_v2.py
COPY train_isolationforest_fixed.py /opt/attacker/train_isolationforest_fixed.py
COPY scripts /opt/attacker/scripts

# ставим зависимости для скриптов (requests + pandas + sklearn и т.д.)
RUN pip install --no-cache-dir requests pandas scikit-learn

# обёртка, которая выполняет последовательность задач
COPY run_all.sh /opt/attacker/run_all.sh
RUN chmod +x /opt/attacker/run_all.sh

# рабочая папка, том будет смонтирован из docker-compose (./results -> /opt/results)
VOLUME ["/opt/results"]

ENTRYPOINT ["/opt/attacker/run_all.sh"]

