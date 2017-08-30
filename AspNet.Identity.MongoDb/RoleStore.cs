using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
// ReSharper disable RedundantExtendsListEntry

namespace AspNet.Identity.MongoDb
{
    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TIdentityClaim">The type of the class representing a role claim.</typeparam>
    public class RoleStore<TRole, TKey, TIdentityClaim> :
        IQueryableRoleStore<TRole>,
        IRoleStore<TRole>,
        IDisposable,
        IRoleClaimStore<TRole>
        where TRole : IdentityRole<TKey, TIdentityClaim>
        where TKey : IEquatable<TKey>
        where TIdentityClaim : IdentityClaim
    {
        #region Constructors

        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        protected RoleStore(IdentityErrorDescriber describer = null)
        {
            ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        /// <inheritdoc />
        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="options">The options used to access the MongoDB.</param>
        public RoleStore(IOptions<MongoDbOptions> options)
            : this(options.Value.ErrorDescriber)
        {
            if (string.IsNullOrWhiteSpace(options.Value?.ConnectionString)) throw new ArgumentNullException("ConnectionString");

            var dbOptions = options.Value;
            var mongoUrl = new MongoUrl(dbOptions.ConnectionString);

            if (string.IsNullOrWhiteSpace(mongoUrl.DatabaseName)) throw new ArgumentNullException("Missing database name in connection string");

            var database = new MongoClient(mongoUrl).GetDatabase(mongoUrl.DatabaseName);
            _roleCollection = database.GetCollection<TRole>(dbOptions.RoleCollectionName ?? DefaultCollectionName);
        }

        /// <inheritdoc />
        /// <summary>
        /// Constructs a new instance of <see cref="T:Microsoft.AspNetCore.Identity.EntityFrameworkCore.RoleStore`5" />.
        /// </summary>
        /// <param name="connectionUri">The connection URI used to access the MongoDB.</param>
        /// <param name="roleCollectionName">The user collection name in MongoDB.</param>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        public RoleStore(string connectionUri, string roleCollectionName = DefaultCollectionName, IdentityErrorDescriber describer = null)
            : this(describer)
        {
            if (string.IsNullOrWhiteSpace(connectionUri)) throw new ArgumentNullException(nameof(connectionUri));
            if (string.IsNullOrWhiteSpace(roleCollectionName)) throw new ArgumentNullException(nameof(roleCollectionName));

            var mongoUrl = new MongoUrl(connectionUri);

            if (string.IsNullOrWhiteSpace(mongoUrl.DatabaseName)) throw new ArgumentNullException("Missing database name in connection string");

            var database = new MongoClient(mongoUrl).GetDatabase(mongoUrl.DatabaseName);
            _roleCollection = database.GetCollection<TRole>(roleCollectionName);
        }

        #endregion

        #region Private Members

        /// <summary>
        /// Indicates whether the object is disposed. Used in Disposable pattern.
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// The role collection.
        /// </summary>
        private readonly IMongoCollection<TRole> _roleCollection;

        #endregion

        #region Public Properties & Constants

        /// <summary>
        /// The default collection name.
        /// </summary>
        public const string DefaultCollectionName = "AspNetRoles";

        /// <summary>
        /// Gets or sets the <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        #endregion

        #region IQueryableRoleStore

        /// <inheritdoc />
        public virtual IQueryable<TRole> Roles => _roleCollection.AsQueryable();

        #endregion

        #region IRoleStore

        /// <inheritdoc />
        public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            try
            {
                await _roleCollection.InsertOneAsync(role, cancellationToken: cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            try
            {
                await _roleCollection.FindOneAndReplaceAsync(u => u.Id.Equals(role.Id), role, null, cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            try
            {
                await _roleCollection.FindOneAndDeleteAsync(u => u.Id.Equals(role.Id), null, cancellationToken);
            }
            catch (Exception e)
            {
                return IdentityResult.Failed(new IdentityError { Description = e.Message });
            }

            return IdentityResult.Success;
        }

        /// <inheritdoc />
        public virtual Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(ConvertIdToString(role.Id));
        }

        /// <inheritdoc />
        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Name);
        }

        /// <inheritdoc />
        public virtual Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            role.Name = roleName;

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task<TRole> FindByIdAsync(string id, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (id == null) throw new ArgumentNullException(nameof(id));

            var roleId = ConvertIdFromString(id);

            return _roleCollection.Find(u => u.Id.Equals(roleId)).SingleOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc />
        public virtual Task<TRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (normalizedName == null) throw new ArgumentNullException(nameof(normalizedName));

            return _roleCollection.Find(u => u.NormalizedName == normalizedName).SingleOrDefaultAsync(cancellationToken);
        }

        /// <inheritdoc />
        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        /// <inheritdoc />
        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            role.NormalizedName = normalizedName;

            return Task.FromResult(0);
        }

        #endregion

        #region IDisposable

        /// <inheritdoc />
        public void Dispose()
        {
            _disposed = true;
        }

        #endregion

        #region IRoleClaimStore

        /// <inheritdoc />
        public virtual Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));

            IList<Claim> result = role.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();

            return Task.FromResult(result);
        }

        /// <inheritdoc />
        public virtual Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            if (!role.Claims.Any(x => x.Equals(claim)))
            {
                var ic = Activator.CreateInstance<TIdentityClaim>();
                ic.ClaimType = claim.Type;
                ic.ClaimValue = claim.Value;
                role.Claims.Add(ic);
            }

            return Task.FromResult(0);
        }

        /// <inheritdoc />
        public virtual Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (role == null) throw new ArgumentNullException(nameof(role));
            if (claim == null) throw new ArgumentNullException(nameof(claim));

            var result = role.Claims.RemoveAll(c => c.Equals(claim));

            return Task.FromResult(result);
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Converts the provided <paramref name="id" /> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey" /> representing the provided <paramref name="id" />.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
                return default(TKey);
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        /// Converts the provided <paramref name="id" /> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="T:System.String" /> representation of the provided <paramref name="id" />.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            return id.Equals(default(TKey)) ? null : id.ToString();
        }

        #endregion

        #region Protected Methods

        /// <summary>Throws if this class has been disposed.</summary>
        protected void ThrowIfDisposed()
        {
            if (_disposed) throw new ObjectDisposedException(GetType().Name);
        }

        #endregion
    }
}
