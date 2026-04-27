using Microsoft.Extensions.DependencyInjection;

namespace MasterPassword.DataAccess.MongoDbAtlas
{
    public static class DataAccessRegistration
    {
        public static IServiceCollection AddDataAccess(this IServiceCollection services, string connectionString)
        {
            return services.AddScoped<IMongoDbRepository, MongoDbRepository>(t => new MongoDbRepository(connectionString));
        }

        public static IServiceCollection AddDataAccess(this IServiceCollection services)
        {
            return services.AddScoped<IMongoDbRepository, MongoDbRepository>();
        }
    }
}
