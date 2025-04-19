FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS base
WORKDIR /app
EXPOSE 8080

# Install wget for healthcheck
RUN apt-get update && apt-get install -y wget

# Add healthcheck using wget instead of curl
HEALTHCHECK --interval=30s \
            --timeout=10s \
            --start-period=30s \
            --retries=3 \
  CMD wget -q -O /dev/null http://localhost:8080/api/health || exit 1

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["ome.API/ome.API.csproj", "ome.API/"]
RUN dotnet restore "ome.API/ome.API.csproj"
COPY . .
WORKDIR "/src/ome.API"
RUN dotnet build "ome.API.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "ome.API.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "ome.API.dll"]