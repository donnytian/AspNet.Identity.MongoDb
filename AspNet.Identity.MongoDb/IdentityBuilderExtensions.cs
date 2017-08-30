using System;
using System.Reflection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AspNet.Identity.MongoDb
{
    /// <summary>
    /// Contains extension methods to <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> for adding MongoDB stores.
    /// </summary>
    public static class IdentityBuilderExtensions
    {
        /// <summary>
        /// Adds an MongoDB implementation of identity information stores.
        /// </summary>
        /// <param name="builder">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</param>
        /// <param name="setupAction">An action to configure the <see cref="T:AspNet.Identity.MongoDb.MongoDbOptions" />.</param>
        /// <returns>The <see cref="T:Microsoft.AspNetCore.Identity.IdentityBuilder" /> instance this method extends.</returns>
        public static IdentityBuilder AddMongoDbStores(this IdentityBuilder builder, Action<MongoDbOptions> setupAction)
        {
            AddStores(builder.Services, builder.UserType, builder.RoleType);
            builder.Services.Configure(setupAction);

            return builder;
        }

        private static void AddStores(IServiceCollection services, Type userType, Type roleType)
        {
            // UserStore
            var genericBaseTypeInfo = FindGenericBaseTypeInfo(userType, typeof(IdentityUser<,,,>));

            if (genericBaseTypeInfo == null) throw new InvalidOperationException($"User type must inherit {typeof(IdentityUser)} or its generic base classes.");

            var genericTypeArgs = genericBaseTypeInfo.GenericTypeArguments;
            var implementationType = typeof(UserStore<,,,,>).MakeGenericType(userType, genericTypeArgs[0], genericTypeArgs[1], genericTypeArgs[2], genericTypeArgs[3]);
            services.TryAddScoped(typeof(IUserStore<>).MakeGenericType(userType), implementationType);

            // RoleStore
            if (roleType != null)
            {
                genericBaseTypeInfo = FindGenericBaseTypeInfo(roleType, typeof(IdentityRole<,>));

                if (genericBaseTypeInfo == null) throw new InvalidOperationException($"Role type must inherit {typeof(IdentityRole)} or its generic base classes.");

                genericTypeArgs = genericBaseTypeInfo.GenericTypeArguments;
                implementationType = typeof(RoleStore<,,>).MakeGenericType(roleType, genericTypeArgs[0], genericTypeArgs[1]);
                services.TryAddScoped(typeof(IRoleStore<>).MakeGenericType(roleType), implementationType);
            }
        }

        private static TypeInfo FindGenericBaseTypeInfo(Type currentType, Type genericBaseType)
        {
            var typeInfo = currentType.GetTypeInfo();

            while (typeInfo.BaseType != null)
            {
                typeInfo = typeInfo.BaseType.GetTypeInfo();
                var type = typeInfo.IsGenericType ? typeInfo.GetGenericTypeDefinition() : null;

                if (type != null && type == genericBaseType)
                {
                    return typeInfo;
                }
            }

            return null;
        }
    }
}
