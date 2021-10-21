build-DassanaEngine:
	mvn compile -DskipTests
	cp -rf ./target/classes/* $(ARTIFACTS_DIR)/

build-DassanaEngineApi:
	mvn compile -DskipTests
	cp -rf ./target/classes/* $(ARTIFACTS_DIR)/

build-DassanaEngineJavaLayer:
	mvn install -DskipTests
	mkdir -p $(ARTIFACTS_DIR)/java/lib
	cp -rf ./target/libs/* $(ARTIFACTS_DIR)/java/lib


build-DassanaEngineApiNative:
	mvn package -Dpackaging=docker-native
	cp -rf ./target/application $(ARTIFACTS_DIR)/
