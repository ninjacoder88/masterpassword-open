using MasterPassword.BusinessLogic.CreateNote;
using MasterPassword.BusinessLogic.CreatePrimaryAccount;
using MasterPassword.BusinessLogic.CreateSecondaryAccount;
using MasterPassword.BusinessLogic.DeleteSecondaryAccount;
using MasterPassword.BusinessLogic.GeneratePassword;
using MasterPassword.BusinessLogic.LoadNotes;
using MasterPassword.BusinessLogic.LoadSecondaryAccount;
using MasterPassword.BusinessLogic.LoadSecondaryAccounts;
using MasterPassword.BusinessLogic.Login;
using MasterPassword.BusinessLogic.RequestHandlers.Logout;
using MasterPassword.BusinessLogic.RequestHandlers.RefreshSession;
using MasterPassword.BusinessLogic.RequestHandlers.UpdateFavicon;
using MasterPassword.BusinessLogic.UpdateNote;
using MasterPassword.BusinessLogic.UpdateSecondaryAccount;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;

namespace MasterPassword.BusinessLogic
{
    internal static class RequestHandlerExtensions
    {
        public static IServiceCollection AddRequestHandlers(this IServiceCollection services)
        {
            return services.AddScoped<ICreatePrimaryAccountRequestHandler, CreatePrimaryAccountRequestHandler>()
                            .AddScoped<ILoginRequestHandler, LoginRequestHandler>()
                            .AddScoped<ILoadShallowSecondaryAccountsRequestHandler, LoadShallowSecondaryAccountsRequestHandler>()
                            .AddScoped<ILoadSecondaryAccountRequestHandler, LoadSecondaryAccountRequestHandler>()
                            .AddScoped<IGeneratePasswordRequestHandler, GeneratePasswordRequestHandler>()
                            .AddScoped<ILoadNotesRequestHandler, LoadNotesRequestHandler>()
                            .AddScoped<ICreateSecondaryAccountRequestHandler, CreateSecondaryAccountRequestHandler>()
                            .AddScoped<ICreateNoteRequestHandler, CreateNoteRequestHandler>()
                            .AddScoped<IUpdateNoteRequestHandler, UpdateNoteRequestHandler>()
                            .AddScoped<IUpdateSecondaryAccountRequestHandler, UpdateSecondaryAccountRequestHandler>()
                            .AddScoped<IDeleteSecondaryAccountRequestHandler, DeleteSecondaryAccountRequestHandler>()
                            .AddScoped<ILogoutRequestHandler, LogoutRequestHandler>()
                            .AddScoped<IRefreshSessionRequestHandler, RefreshSessionRequestHandler>()
                            .AddScoped<IUpdateFaviconRequestHandler, UpdateFaviconRequestHandler>()
                            .AddSingleton<IMemoryCache, MemoryCache>();
        }
    }
}
