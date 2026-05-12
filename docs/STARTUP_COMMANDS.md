cd d:/fyp_se/backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload

cd d:/fyp_se/backend
python -m orchestration.graph

cd d:/fyp_se/backend
python -m bridge.wazuh_kafka_bridge

cd d:/fyp_se/backend
python -m scripts.synthetic_log_generator --eps 10 --duration 60

cd d:/fyp_se/frontend
npm run dev

cd d:/fyp_se/frontend
npm run web
