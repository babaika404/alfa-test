FROM eclipse-temurin:25-jdk AS build
WORKDIR /app
COPY . .
RUN ./mvnw clean package -DskipTests

FROM eclipse-temurin:25-jre
WORKDIR /app

RUN groupadd appgroup && useradd -g appgroup -s /bin/sh appuser
RUN mkdir -p /app/data /app/downloads

COPY --from=build --chown=appuser:appgroup /app/target/*.jar app.jar
COPY --chown=appuser:appgroup entrypoint.sh .
RUN chmod +x entrypoint.sh && chown -R appuser:appgroup /app/data /app/downloads

USER appuser

EXPOSE 10001

ENTRYPOINT ["./entrypoint.sh"]