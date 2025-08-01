#!/usr/bin/env bash
set -euo pipefail

# Начало всего процесса
start_total=$(date +%s)

# 🧱 Генерируем base64-файл
start_gen=$(date +%s)
# Для GNU base64: -w0 отключает разбиение строки
head -c 1024M /dev/urandom | base64 -w0 > input.b64
echo "Генерация заняла $(( $(date +%s) - start_gen )) секунд"

# 🔐 Отправка на /encode (Axum) — формируем POST с чистым бинарным телом
start_enc=$(date +%s)
curl --fail --data-binary "@input.b64" \
     --header "Content-Type: application/octet-stream" \
     http://localhost:8080/encode \
     -o encrypted.b64.enc
echo "Encode (сжатие + шифрование) занял $(( $(date +%s) - start_enc )) секунд"

# 🔓 Отправка на /decode (Axum) — снова чистый бинарный поток
start_dec=$(date +%s)
if ! curl --fail --data-binary "@encrypted.b64.enc" \
        --header "Content-Type: application/octet-stream" \
        http://localhost:8080/decode \
        -o output.b64; then
    echo "‼️ Warning: decode curl failed, но продолжаем"
fi
echo "Decode занял $(( $(date +%s) - start_dec )) секунд"

# ✅ Проверка целостности
if cmp --silent input.b64 output.b64; then
    echo "✅ Round‑trip SUCCESS — файлы идентичны"
else
    echo "❌ Round‑trip FAILED — файлы различаются"
    exit 1
fi

# 🗑 Удаляем временные файлы
rm -v input.b64 encrypted.b64.enc output.b64

echo "Общее время: $(( $(date +%s) - start_total )) секунд"
