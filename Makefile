clean:
	docker-compose down --rmi all -v
down:
	docker-compose down
buildup:
	docker-compose up --build
up:
	docker compose up
restart:
	make clean && make up
logs:
	docker-compose logs
perf:
	k6 run ./k6/session.js