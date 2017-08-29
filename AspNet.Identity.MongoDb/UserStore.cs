using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
// ReSharper disable RedundantExtendsListEntry

namespace AspNet.Identity.MongoDb
{
    /// <summary>
    /// Represents a new instance of a persistence store for the specified user and role types.
    /// </summary>
    /// <typeparam name="TUser">The type representing a user.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TIdentityClaim">The type representing a claim.</typeparam>
    /// <typeparam name="TIdentityUserLogin">The type representing a user external login.</typeparam>
    /// <typeparam name="TUserToken">The type representing a user token.</typeparam>
    public class UserStore<TUser, TKey, TIdentityClaim, TIdentityUserLogin, TUserToken> :
        IUserLoginStore<TUser>,
        IUserStore<TUser>,
        IDisposable,
        IUserClaimStore<TUser>,
        IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>,
        IUserEmailStore<TUser>,
        IUserLockoutStore<TUser>,
        IUserPhoneNumberStore<TUser>,
        IQueryableUserStore<TUser>,
        IUserTwoFactorStore<TUser>,
        IUserAuthenticationTokenStore<TUser>,
        IUserAuthenticatorKeyStore<TUser>,
        IUserTwoFactorRecoveryCodeStore<TUser>
        where TUser : IdentityUser<TKey, TIdentityClaim, TIdentityUserLogin, TUserToken>
        where TKey : IEquatable<TKey>
        where TIdentityClaim : IdentityClaim, new()
        where TIdentityUserLogin : IdentityUserLogin, new()
        where TUserToken : IdentityUserToken, new()
    {
        #region Constructors

        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        protected UserStore(IdentityErrorDescriber describer = null)
        {
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        /// <inheritdoc />
        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="connectionUri">The connection URI used to access the MongoDB.</param>
        /// <param name="userCollectionName">The user collection name in MongoDB.</param>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        public UserStore(string connectionUri, string userCollectionName = DefaultCollectionName, IdentityErrorDescriber describer = null)
          : this(describer ?? new IdentityErrorDescriber())
        {
            if (string.IsNullOrWhiteSpace(connectionUri)) throw new ArgumentNullException(nameof(connectionUri));
            if (string.IsNullOrWhiteSpace(userCollectionName)) throw new ArgumentNullException(nameof(userCollectionName));

            var mongoUrl = new MongoUrl(connectionUri);

            if (string.IsNullOrWhiteSpace(mongoUrl.DatabaseName)) throw new ArgumentNullException("Missing database name in connection string");

            _database = new MongoClient(mongoUrl).GetDatabase(mongoUrl.DatabaseName);
            _collectionName = userCollectionName;
        }

        /// <inheritdoc />
        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="databse">The database object.</param>
        /// <param name="userCollectionName">The role collection name in MongoDB.</param>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        public UserStore(IMongoDatabase databse, string userCollectionName = DefaultCollectionName, IdentityErrorDescriber describer = null)
          : this(describer ?? new IdentityErrorDescriber())
        {
            if (string.IsNullOrWhiteSpace(userCollectionName)) throw new ArgumentNullException(nameof(userCollectionName));

            _database = databse ?? throw new ArgumentNullException(nameof(databse));
            _collectionName = userCollectionName;
        }

        #endregion

        #region Private Members

        /// <summary>
        /// Indicates whether the object is disposed. Used in Disposable pattern.
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// The default collection name.
        /// </summary>
        private const string DefaultCollectionName = "AspNetUsers";

        /// <summary>
        /// The underline MongoDb database
        /// </summary>
        private readonly IMongoDatabase _database;

        /// <summary>
        /// The user collection name.
        /// </summary>
        private readonly string _collectionName;

        private IMongoCollection<TUser> UserCollection => _database.GetCollection<TUser>(_collectionName);

        #endregion

        #region Public Properties & Constants

        /// <summary>
        /// Gets or sets the <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        public const string DefaultLoginProvider = "[AspNetUserStore]";
        public const string DefaultAuthenticationTokenName = "AuthenticatorKey";
        public const string DefaultTwoFactorRecoveryCodeTokenName = "RecoveryCodes";

        #endregion

        #region Public Methods

        /// <summary>
        /// Converts the provided <paramref name="id" /> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey" /> representing the provided <paramref name="id" />.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null) return default(TKey);

            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        /// Converts the provided <paramref name="id" /> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="T:System.String" /> representation of the provided <paramref name="id" />.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            return Equals(id, default(TKey)) ? null : id.ToString();
        }

        #endregion

        #region IUserLoginStore

        /// <inheritdoc />
        public Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (login == null) throw new ArgumentNullException(nameof(login));

            if (!user.Logins.Any(x => x.LoginProvider == login.LoginProvider && x.ProviderKey == login.ProviderKey))
            {
                user.Logins.Add(new TIdentityUserLogin
                {
                    LoginProvider = login.LoginProvider,
                    ProviderKey = login.ProviderKey,
                    ProviderDisplayName = login.ProviderDisplayName
                });
            }

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            var result = user.Logins.RemoveAll(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            IList<UserLoginInfo> list = user.Logins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.ProviderDisplayName)).ToList();

            return Task.FromResult(list);
        }

        /// <inheritdoc />
        public Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return UserCollection
                .Find(u => u.Logins.Any(l => l.LoginProvider == loginProvider && l.ProviderKey == providerKey))
                .SingleOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region IUserStore

        /// <inheritdoc />
        public virtual Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(ConvertIdToString(user.Id));
        }

        /// <inheritdoc />
        public virtual Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.UserName);
        }

        /// <inheritdoc />
        public virtual Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.UserName = userName;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedUserName);
        }

        /// <inheritdoc />
        public virtual Task SetNormalizedUserNameAsync(TUser user, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.NormalizedUserName = normalizedName;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            try
            {
                await UserCollection.InsertOneAsync(user, cancellationToken: cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            try
            {
                await UserCollection.FindOneAndReplaceAsync(u => u.Id.Equals(user.Id), user, null, cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            try
            {
                await UserCollection.FindOneAndDeleteAsync(u => u.Id.Equals(user.Id), null, cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException(nameof(userId));

            return await UserCollection.Find(u => u.Id.Equals(userId)).SingleOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc />
        public virtual async Task<TUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(normalizedUserName)) throw new ArgumentException(nameof(normalizedUserName));

            return await UserCollection.Find(u => u.NormalizedUserName == normalizedUserName).SingleOrDefaultAsync(cancellationToken);
        }

        #endregion

        #region IDisposable

        /// <inheritdoc />
        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IUserClaimStore

        /// <inheritdoc />
        public virtual Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            IList<Claim> result = user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public virtual Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

            foreach (var claim in claims)
            {
                if (user.Claims.Any(x => x.Equals(claim)))
                {
                    continue;
                }

                var ic = Activator.CreateInstance<TIdentityClaim>();
                ic.ClaimType = claim.Type;
                ic.ClaimValue = claim.Value;
                user.Claims.Add(ic);
            }

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claim == null) throw new ArgumentNullException(nameof(claim));
            if (newClaim == null) throw new ArgumentNullException(nameof(newClaim));

            if (!user.Claims.Any(c => c.Equals(claim)))
            {
                return Task.FromResult(false);
            }

            user.Claims.RemoveAll(c => c.Equals(claim));

            var ic = Activator.CreateInstance<TIdentityClaim>();
            ic.ClaimType = claim.Type;
            ic.ClaimValue = claim.Value;
            user.Claims.Add(ic);

            user.Claims.Add(ic);

            return Task.FromResult(true);
        }

        /// <inheritdoc />
        public virtual Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (claims == null) throw new ArgumentNullException(nameof(claims));

            foreach (var claim in claims)
            {
                user.Claims.RemoveAll(c => c.Equals(claim));
            }

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual async Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            return await UserCollection.Find(u => u.Claims.Any(c => c.Equals(claim))).ToListAsync(cancellationToken);
        }

        #endregion

        #region IUserPasswordStore

        /// <inheritdoc />
        public virtual Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.PasswordHash = passwordHash;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PasswordHash);
        }

        /// <inheritdoc />
        public virtual Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PasswordHash != null);
        }

        #endregion

        #region IUserSecurityStampStore

        /// <inheritdoc />
        public virtual Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.SecurityStamp = stamp;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.SecurityStamp);
        }

        #endregion

        #region IUserEmailStore

        /// <inheritdoc />
        public virtual Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.Email = email;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.Email);
        }

        /// <inheritdoc />
        public virtual Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.EmailConfirmed);

        }

        /// <inheritdoc />
        public virtual Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.EmailConfirmed = confirmed;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<TUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(normalizedEmail)) throw new ArgumentException(nameof(normalizedEmail));

            return UserCollection.Find(u => u.NormalizedEmail == normalizedEmail).SingleOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc />
        public virtual Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.NormalizedEmail);
        }

        /// <inheritdoc />
        public virtual Task SetNormalizedEmailAsync(TUser user, string normalizedEmail, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.NormalizedEmail = normalizedEmail;

            return Task.FromResult(0);
        }

        #endregion

        #region IUserLockoutStore

        /// <inheritdoc />
        public virtual Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnd);
        }

        /// <inheritdoc />
        public virtual Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.LockoutEnd = lockoutEnd;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.AccessFailedCount++;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.AccessFailedCount = 0;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.AccessFailedCount);
        }

        /// <inheritdoc />
        public virtual Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.LockoutEnabled);
        }

        /// <inheritdoc />
        public virtual Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.LockoutEnabled = enabled;

            return Task.FromResult(0);
        }

        #endregion

        #region IUserPhoneNumberStore

        /// <inheritdoc />
        public virtual Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.PhoneNumber = phoneNumber;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumber);
        }

        /// <inheritdoc />
        public virtual Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <inheritdoc />
        public virtual Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(0);
        }

        #endregion

        #region IQueryableUserStore

        /// <inheritdoc />
        public virtual IQueryable<TUser> Users => UserCollection.AsQueryable();

        #endregion

        #region IUserTwoFactorStore

        /// <inheritdoc />
        public virtual Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            user.TwoFactorEnabled = enabled;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return Task.FromResult(user.TwoFactorEnabled);
        }

        #endregion

        #region IUserAuthenticationTokenStore

        /// <inheritdoc />
        public virtual Task SetTokenAsync(TUser user, string loginProvider, string name, string value, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (loginProvider == null) throw new ArgumentNullException(nameof(loginProvider));
            if (name == null) throw new ArgumentNullException(nameof(name));

            var token = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);

            user.Tokens.RemoveAll(t => t.LoginProvider == loginProvider && t.Name == name);

            if (token == null)
            {
                token = Activator.CreateInstance<TUserToken>();
                token.LoginProvider = loginProvider;
                token.Name = name;
            }

            token.Value = value;
            user.Tokens.Add(token);

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task RemoveTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (loginProvider == null) throw new ArgumentNullException(nameof(loginProvider));
            if (name == null) throw new ArgumentNullException(nameof(name));

            var result = user.Tokens.RemoveAll(t => t.LoginProvider == loginProvider && t.Name == name);

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public virtual Task<string> GetTokenAsync(TUser user, string loginProvider, string name, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (loginProvider == null) throw new ArgumentNullException(nameof(loginProvider));
            if (name == null) throw new ArgumentNullException(nameof(name));

            var token = user.Tokens.FirstOrDefault(t => t.LoginProvider == loginProvider && t.Name == name);

            return Task.FromResult(token?.Value);

        }

        #endregion

        #region IUserAuthenticatorKeyStore

        /// <inheritdoc />
        public virtual Task SetAuthenticatorKeyAsync(TUser user, string key, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (key == null) throw new ArgumentNullException(nameof(key));

            return SetTokenAsync(user, DefaultLoginProvider, DefaultAuthenticationTokenName, key, cancellationToken);
        }

        /// <inheritdoc />
        public virtual Task<string> GetAuthenticatorKeyAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            return GetTokenAsync(user, DefaultLoginProvider, DefaultAuthenticationTokenName, cancellationToken);
        }

        #endregion

        #region IUserTwoFactorRecoveryCodeStore

        /// <inheritdoc />
        public virtual Task ReplaceCodesAsync(TUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (recoveryCodes == null) throw new ArgumentNullException(nameof(recoveryCodes));

            string str = string.Join(";", recoveryCodes);
            return SetTokenAsync(user, DefaultLoginProvider, DefaultTwoFactorRecoveryCodeTokenName, str, cancellationToken);
        }

        /// <inheritdoc />
        public virtual async Task<bool> RedeemCodeAsync(TUser user, string code, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));
            if (code == null) throw new ArgumentNullException(nameof(code));

            var strArray = (await GetTokenAsync(user, DefaultLoginProvider, DefaultTwoFactorRecoveryCodeTokenName, cancellationToken) ?? "").Split(';');
            if (!strArray.Contains(code))
            {
                return false;
            }

            var stringList = new List<string>(strArray.Where(s => s != code));
            await ReplaceCodesAsync(user, stringList, cancellationToken);

            return true;
        }

        /// <inheritdoc />
        public virtual async Task<int> CountCodesAsync(TUser user, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null) throw new ArgumentNullException(nameof(user));

            var str = await GetTokenAsync(user, DefaultLoginProvider, DefaultTwoFactorRecoveryCodeTokenName, cancellationToken) ?? "";

            return str.Length <= 0 ? 0 : str.Split(';').Length;
        }

        #endregion

        #region Protected Methods

        /// <summary>Throws if this class has been disposed.</summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        #endregion
    }
}
