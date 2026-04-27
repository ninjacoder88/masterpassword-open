using MasterPassword.BusinessLogic.RequestHandlers;
using Microsoft.Extensions.DependencyInjection;

namespace MasterPassword.BusinessLogic
{
    public static class BusinessLogicRegistration
    {
        public static IServiceCollection AddBusinessLogic(this IServiceCollection services)
        {
            return services.AddRequestHandlers()
                .AddSingleton<IEncryptor, Encryptor>()
                .AddSingleton<ITokenGenerator, TokenGenerator>()
                .AddSingleton<IKeyDeriver, KeyDeriver>();
        }
    }
}
