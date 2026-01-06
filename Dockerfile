FROM eclipse-temurin:25-jdk AS build
WORKDIR /app
COPY . .

RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:25-jre
WORKDIR /app

RUN mkdir -p /app/data

COPY --from=build /app/target/*.jar app.jar
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

EXPOSE 10001

ENTRYPOINT ["./entrypoint.sh"]
