using Microsoft.AspNetCore.Http;
using System;

namespace MasterPassword.Extension
{
    public static class HttpContextExtensions
    {
        //private const string SessionVariable_IsLoggedIn = "IsLoggedIn";
        //private const string SessionVariable_Username = "Username";
        private const string SessionVariable_UserId = "UserId";
        private const string SessionVariable_UserKey = "UserKey";
        private const string SessionVariable_TokenExpiration = "TokenExpiration";

        //public static bool IsLoggedIn(this HttpContext context)
        //{
        //    return context?.Session?.GetString(SessionVariable_IsLoggedIn) == "true";
        //}

        //public static string GetUsername(this HttpContext context)
        //{
        //    return context?.Session?.GetString(SessionVariable_Username);
        //}

        public static string GetUserId(this HttpContext context)
        {
            return context?.Session?.GetString(SessionVariable_UserId);
        }

        public static string GetUserKey(this HttpContext context)
        {
            return context?.Session?.GetString(SessionVariable_UserKey);
        }

        public static DateTimeOffset GetTokenExpiration(this HttpContext context)
        {
            var tokenExpiration = context?.Session.GetString(SessionVariable_TokenExpiration);
            if (!DateTimeOffset.TryParse(tokenExpiration, out DateTimeOffset expires))
                return new DateTimeOffset();
            return expires;
        }

        public static void Login(this HttpContext context, string id, string userKey, DateTimeOffset tokenExpiration)
        {
            //context?.Session?.SetString(SessionVariable_IsLoggedIn, "true");
            context?.Session?.SetString(SessionVariable_UserId, id);
            //context?.Session?.SetString(SessionVariable_Username, username);
            context?.Session?.SetString(SessionVariable_UserKey, userKey);
            context?.Session?.SetString(SessionVariable_TokenExpiration, tokenExpiration.ToString());
        }

        public static void Refresh(this HttpContext context, string id, DateTimeOffset tokenExpiration)
        {
            //context?.Session?.SetString(SessionVariable_IsLoggedIn, "true");
            context?.Session?.SetString(SessionVariable_UserId, id);
            //context?.Session?.SetString(SessionVariable_Username, username);
            //context?.Session?.SetString(SessionVariable_UserKey, userKey);
            context?.Session?.SetString(SessionVariable_TokenExpiration, tokenExpiration.ToString());
        }

        public static void Logout(this HttpContext context)
        {
            //context?.Session?.SetString(SessionVariable_IsLoggedIn, "false");
            //context?.Session?.SetString(SessionVariable_Username, string.Empty);
            context?.Session?.SetString(SessionVariable_UserId, string.Empty);
            context?.Session?.SetString(SessionVariable_UserKey, string.Empty);
            context?.Session?.SetString(SessionVariable_TokenExpiration, string.Empty);
        }
    }
}
