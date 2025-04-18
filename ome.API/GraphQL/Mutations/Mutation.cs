namespace ome.API.GraphQL.Mutations;

public class Mutation {
    /// <summary>
    /// Warmup Methode für den Healthcheck und WS 
    /// </summary>
    public Task<string> PingAsync() => Task.FromResult("pong");
}