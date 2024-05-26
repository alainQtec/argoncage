function Import-SQLiteDlls {
    # .SYNOPSIS
    #     Imports database assembly and Interop DLLs
    # .DESCRIPTION
    #    Uses API method to load Interop databases and the .NET assembly
    [CmdletBinding()]
    param ()
    begin {
        $code = '
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibrary(string dllToLoad);
        [DllImport("kernel32.dll")]
        public static extern bool FreeLibrary(IntPtr hModule);'
        Add-Type -MemberDefinition $code -Namespace Internal -Name Helper
        Set-Variable parentFolder -Value (Split-Path -Path $PSScriptRoot)
        $UseVerbose = $VerbosePreference -eq "continue"
        $Path = [IO.Path]::Combine($PSScriptRoot, 'bin', "x$(if ([Environment]::Is64BitProcess) { 64 } else { 86 })", 'SQLite.Interop.dll')
    }
    process {
        if ('Internal.Helper' -as 'type' -isnot [type]) {
            if (![IO.File]::Exists($Path)) {
                Throw [System.DllNotFoundException]::new("Platform SQLite dll not found", [System.IO.FileNotFoundException]::New("Could not find file $Path"))
            }
            $null = [Internal.Helper]::LoadLibrary($Path)
            if ($UseVerbose) { Write-Host "VERBOSE: Loaded Interop assembly" -f Blue }
        }
        Add-Type -Path ([IO.Path]::Combine($PSScriptRoot, 'bin', 'System.Data.SQLite.dll'))
        if ($UseVerbose) { Write-Host "VERBOSE: SQLite dlls loaded successfully" -f Green }
        # TODO: Fix this error that occurs when I run: $db = New-Database -Path /tmp/database1.db
        #
        # PS /home/alain> $db.InvokeSql('Select * from customers')
        # New-Object: Exception calling ".ctor" with "1" argument(s): "Unable to load shared library 'SQLite.Interop.dll' or one of its dependencies. In order to help diagnose loading
        # problems, consider using a tool like strace. If you're using glibc, consider setting the LD_DEBUG environment variable:  /usr/lib/powershell-7/SQLite.Interop.dll.so:
        #
        # Fix attempt 1: but it failed :(
        # $pwshparentFolder = ((Get-Command pwsh).Source | Split-Path)
        # if (![IO.File]::Exists([IO.Path]::Combine($pwshparentFolder, (Split-Path $Path -Leaf)))) {
        #     if ($(Get-Variable IsLinux -Value)) {
        #         Write-Host "sudo cp: Enter password to copying dll file to $pwshparentFolder" -f Blue
        #         sudo cp -v -u $Path $pwshparentFolder
        #     } else {
        #         Copy-Item $Path -Destination $pwshparentFolder -Force
        #     }
        # }
    }
}

class DatabaseField {
    [Table]$Table
    [string]$Name
    [string]$Type
    [bool]$NotNull
    [object]$DefaultValue
    [int]$Id

    DatabaseField([Table]$Table, [System.Data.DataRow]$ColumnInfo) {
        # the constructor takes the table object plus the datarow returned by the database with the column details
        # Translates the raw datarow information to the Column object properties
        $this.Name = $ColumnInfo.Name
        $this.Type = $ColumnInfo.type
        $this.NotNull = $ColumnInfo.notnull
        $this.DefaultValue = $ColumnInfo.dflt_value
        $this.Table = $Table
        $this.Id = $ColumnInfo.cid
    }
    [void] AddIndex() {
        $tbl = $this.Table
        $clm = $this.Name
        $existingIndex = $tbl.GetIndexes() | Where-Object { $_.Column.Name -eq $this.Name } | Select-Object -First 1
        if ($null -ne $existingIndex) {
            $existing = $existingIndex.Name
            throw "$clm uses index $existing already. Remove this index before adding a new one."
        }
        $columnName = $this.Name
        $tableName = $this.Table.Name
        $indexName = "idx_" + $this.Name
        $database = $this.Table.Database
        $database.AddIndex($indexName, $tableName, $columnName, $false)
    }
    [void] AddUniqueIndex() {
        $columnName = $this.Name
        $tableName = $this.Table.Name
        $indexName = "idx_" + $this.Name
        $database = $this.Table.Database

        $database.AddIndex($indexName, $tableName, $columnName, $true)
    }
    [void] DropIndex() {
        $indexes = $this.Table.GetIndexes()[$this.Name]
        foreach ($index in $indexes) {
            $sql = "Drop Index If Exists $($index.Name)"
            $this.Table.Database.InvokeSqlNoResult($sql)
        }
    }
    [string] ToString() {
        return '{0} ({1})' -f $this.Name, $this.Type
    }
}

# this class represents a single property
# it specifies the property name and the property value type
class NewFieldRequest {
    [string]$Name
    [string]$Type

    NewFieldRequest([string]$Name, [string]$Type) {
        $this.Name = $Name
        $this.Type = $Type
    }
    [string]ToString() {
        if ($this.Type -eq 'String') {
            return "'{0}' '{1}' COLLATE NOCASE" -f $this.Name, $this.Type
        }
        return "'{0}' '{1}'" -f $this.Name, $this.Type
    }
}

# .SYNOPSIS
# SQLite database representation
# .NOTES
# requires the SQLite DLLs to be preloaded
class Database {
    [string] $Path
    [object] $Connection
    [bool] $IsOpen = $false
    [int] $QueryTimeout = 500 # milliseconds
    hidden [bool] $_enableUnsafePerformanceMode = $false
    hidden [bool] $_lockDatabase = $false
    hidden [string] $_path
    Database([string]$Path) {
        # The file does not need to exist yet. It will be created if it does not yet exist.
        # If the path is ":memory:", then a memory-based database is created
        if ($Path -ne ':memory:') {
            $this.Path = $Path
            $Isvalid = Test-Path -Path $Path -IsValid
            if (!$Isvalid) {
                throw [System.ArgumentException]::new("Path is invalid: $Path")
            }
            $extension = [IO.Path]::GetExtension($this.Path)
            if ($extension -ne '.db') {
                Write-Verbose "Database files should use the extension '.db'. You are using extension '$extension'."
            }
            $resolved = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
            if ($resolved -ne $Path) {
                Write-Verbose "Absolute file paths preferred. Your path '$Path' resolved to '$resolved'"
                $this.Path = $resolved
            }
            $this._path = $this.Path
        } else {
            # save the path in hidden field
            $this._path = $Path
            $this.Path = '[memory]'
        }
        # .SYNOPSIS
        #  ScriptProperty : EnableUnsafePerformanceMode
        # .DESCRIPTION
        #  When a new value is assigned, the database changes
        #  When this property is set to $true, a number of database features
        #  are changed to increase performance at the expense of safety
        #  - the journal is switched to MEMORY which might cause data corruption when the
        #    script crashes in the middle of adding new data
        #  - database synchronization is turned off which can cause data corruption when the database crashes
        $this | Add-Member -MemberType ScriptProperty -Name EnableUnsafePerformanceMode -Value { $this._enableUnsafePerformanceMode } -SecondValue {
            param($enable)
            # a hidden property is used to store the desired mode
            $this._enableUnsafePerformanceMode = $enable
            # if the database is open already, the change is made immediately
            # else, the change is performed later whenever Open() is called
            if ($this.IsOpen) {
                if ($enable) {
                    $mode1 = 'OFF'
                    $mode2 = 'MEMORY'
                } else {
                    $mode1 = 'ON'
                    $mode2 = 'DELETE'
                }
                $this.InvokeSqlNoResult("PRAGMA JOURNAL_MODE=$mode2")
                $this.InvokeSqlNoResult("PRAGMA SYNCHRONOUS=$mode1")
            }
        }
        # .SYNOPSIS
        # "LockDatabase"
        # .DESCRIPTION
        #  To increase performance, the database file can be locked
        # when the database file is locked, no other can access, delete, copy or move the file
        $this | Add-Member -MemberType ScriptProperty -Name LockDatabase -Value { $this._lockDatabase } -SecondValue {
            param($enable)
            $this._lockDatabase = $enable
            if ($this.IsOpen) {
                if ($enable) {
                    $mode = 'exclusive'
                } else {
                    $mode = 'normal'
                }
                $this.InvokeSqlNoResult("PRAGMA LOCKING_MODE=$mode")
            }
        }
        # database file size
        $this | Add-Member -MemberType ScriptProperty -Name FileSize -Value {
            if ($this._Path -eq ':memory:') {
                'In-Memory Database'
            } else {
                $exists = Test-Path -Path $this.Path -PathType Leaf
                if ($exists) {
                    "{0:n0} KB" -f (Get-Item -LiteralPath $this.Path).Length
                } else {
                    'no file created yet'
                }
            }
        }
    }
    # Send a SQL statement to the database
    # this method is used for sql statements that do not return anything
    [void] InvokeSqlNoResult([string]$Sql) {
        # the database is opened in case it is not open yet
        # if it is open already, the call does nothing
        # generally, the database is kept open after all methods
        # it is closed only when PowerShell ends, or when Close() is called
        # explicitly
        $this.Open()
        # create an SQL command and use the default timeout set in the database property
        $cmd = $this.Connection.CreateCommand()
        $cmd.CommandText = $Sql
        $cmd.CommandTimeout = $this.QueryTimeout
        $null = $cmd.ExecuteNonQuery()
        # the command object is disposed to free its memory
        $cmd.Dispose()
    }
    # similar to InvokeSqlNoResult, however this method does return data to the caller
    [System.Data.DataRow[]] InvokeSql([string]$Sql) {
        $this.Open()
        $cmd = $this.Connection.CreateCommand()
        $cmd.CommandText = $Sql
        $cmd.CommandTimeout = $this.QueryTimeout
        # create a new empty dataset. It will be filled with the results later
        $ds = [System.Data.DataSet]::new()
        # create a new data adapter based on the sql command
        $da = New-Object System.Data.SQLite.SQLiteDataAdapter($cmd)
        $null = $da.fill($ds)
        $cmd.Dispose()
        return $ds.Tables.Rows
    }
    [System.Data.DataRow[]] InvokeSql([string]$Sql, [bool]$CaseSensitive) {
        # remove all collate statements
        $sql = $sql -replace 'collate\s{1,}(binary|nocase|rtrim)\s{0,}'
        if ($CaseSensitive) {
            $sql += " collate binary"
        } else {
            $sql += " collate nocase"
        }
        return $this.InvokeSql($sql)
    }
    # .SYNOPSIS
    #  Explicitly closes the database
    # .DESCRIPTION
    #  Any method acting on the database will open the database
    #  and keep it open, so consecutive methods can reuse the open connection
    # .NOTES
    #  The database always get closed when PowerShell session ends
    #  To explicitly close the database, Close() must be called
    [void] Close() {
        # closes the current database connection
        # this is a CRITICAL operation for databases stored solely in memory
        # while file-based databases keep the data, memory-based databases are deleted
        # including all data collected inside of them
        if ($this.IsOpen) {
            $this.Connection.Close()
            $this.Connection.Dispose()
            # set the property to $null so when a user views the database
            # object, the old connection no longer shows up
            $this.Connection = $null
            $this.IsOpen = $false
        }
    }
    # Whenever a method wants to access the database, it must have an open connection
    [void] Open() {
        if ($this.IsOpen) {
            # if the database connection is already open, bail out:
            return
        }
        # create a new database connection using the path as connection string
        $ConnectionString = 'Data Source={0}' -f $this._path
        $_connectionObject = New-Object System.Data.SQLite.SQLiteConnection($ConnectionString)
        if ($_ -as 'System.Data.SQLite.SQLiteConnection' -is 'System.Data.SQLite.SQLiteConnection') {
            $this.Connection = $_connectionObject
        } else {
            throw "Could not createe a valid SQLite connection"
        }
        # set this property to $true to allow UNC paths to work
        $this.Connection.ParseViaFramework = $true
        $this.Connection | Add-Member -MemberType ScriptMethod -Name ToString -Force -Value {
            # display the sqlite server version, the currently used memory in KB, and the state
            '{1:n0} KB,{2},V{0}' -f $this.ServerVersion, ($this.MemoryUsed / 1KB), $this.State
        }

        # open the database connection
        Try {
            $this.Connection.Open()
        } Catch {
            # if the database cannot be opened, throw an exception
            # there are many different reasons why opening the database may fail. Here are some:
            # - the database file does not exist (should be validated by New-Database)
            # - the user has no write permission to the database file
            #   - it may reside in a restricted place, i.e. the c:\ root folder
            #   - it may be locked by another application
            # - there is not enough free space on the drive left
            #
            # Unfortunately, the internally thrown exception does not provide a clue
            # it just complains that opening the database file did not work
            # so we cannot provide detailed guidance
            $message = "Cannot open database. You may not have sufficient write perission at this location, or the drive is full. Database file: $($this._path). Original error message: $($_.Exception.Message)"
            throw [System.InvalidOperationException]::new($message)
        }

        # set the state property accordingly:
        $this.IsOpen = $true
        # there are a number of performance options that a user can specify
        # these options do not take effect until the database is opened
        # so now that the database is open, the requested changes are applied
        # the requests are stored in hidden properties
        if ($this._enableUnsafePerformanceMode) { $this.EnableUnsafePerformanceMode = $true }
        if ($this._lockDatabase) { $this.LockDatabase = $true }
    }
    # returns all tables in the database as an ordered hashtable equivalent
    # a hashtable is used to make it easier to access a table directly via code
    # and also to provide a fast way of looking up tables
    # for example, thanks to the hashtable, code like this is possible:
    # $db.GetTables().masterTable.GetColumns()
    # an ordered hashtable is used to get an ordered list of tables without
    # having to sort anything again
    [System.Collections.Specialized.OrderedDictionary] GetTables() {
        $sql = "SELECT * FROM sqlite_master WHERE type='table' ORDER BY name;"
        $tables = $this.InvokeSql($sql)
        # create an empty ordered hashtable which really is a special case of
        # a dictionary
        $hash = [Ordered]@{}

        # add the tables to the hashtable
        foreach ($row in $tables) {
            # use the table name as key, and create a Table object for the table
            $hash[$row.Name] = [Table]::new($this, $row)
        }
        return $hash
    }
    [Table] GetTable([string]$TableName) {
        # sqlite queries are case-sensitive. Since tables with a given name can exist
        # only once, regardless of casing, the search needs to be case-insensitive
        # for this to happen, add COLLATE NOCASE to the sql statement
        $sql = "SELECT * FROM sqlite_master WHERE type='table' and Name='$TableName' COLLATE NOCASE"
        $tables = $this.InvokeSql($sql)
        if ($null -eq $tables) {
            return $null
        }
        return [Table]::new($this, $tables[0])
    }
    # TODO: make this static
    # it takes any object and returns an array of ColumnInfo objects describing
    # the properties and their data types
    # this information can be used to construct a table definition based on any
    # object type
    [NewFieldRequest[]] GetFieldNamesFromObject([object]$data) {
        # get all members from the object via the hidden PSObject property
        $names = [object[]]$data.psobject.Members |
            # select properties only
            # (including dynamicly added properties such as ScriptProperties)
            Where-Object { $_.MemberType -like '*Property' } |
            # determine the appropriate data type and construct the ColumnInfo object
            ForEach-Object {
                $name = $_.Name
                # take the string name of the data type
                $type = $_.TypeNameOfValue
                # if there is no specific type defined, and if the object property
                # contains data, use the type from the actual value of the property
                if (($type -eq 'System.Object' -or $type -like '*#*') -and $null -ne $_.Value) {
                    $type = $_.Value.GetType().FullName
                }
                # remove the System namespace.
                if ($type -like 'System.*') { $type = $type.Substring(7) }
                # any complex and specific type now contains one or more "."
                # since the database supports only basic types, for complex types
                # the string datatype is used instead
                if ($type -like '*.*') { $type = 'String' }
                if ($type -eq 'boolean') { $type = 'Bool' }
                # create the ColumnInfo object
                [NewFieldRequest]::new($name, $type)
            }
        # return the array of ColumnInfo objects that represent each
        # object property
        return $names
    }
    [void] AddIndex([string]$Name, [string]$TableName, [string[]]$ColumnName, [bool]$Unique) {
        $UniqueString = ('', 'UNIQUE ')[$Unique]
        $ColumnString = $columnName -join ', '
        $sql = "Create $UniqueString Index $Name On $TableName ($columnString);"

        # creating an index may take a long time, so take a look at the table size
        $table = $this.GetTable($TableName)
        if ($null -eq $table) {
            throw "Table $table not found."
        } elseif ($table.Count -gt 10000) {
            Write-Warning "Creating an index on large tables may take considerable time. Please be patient."
        }
        try {
            $this.InvokeSqlNoResult($sql)
        } catch {
            if ($Unique -and $_.Exception.InnerException.Message -like '*constraint*') {
                throw "There are datasets in your table that share the same values, so a unique index cannot be created. Try a non-unique index instead."
            }
            throw $_.Exception
        }
    }
    # backup the database to a file
    # this can also be used to save an in-memory-database to file
    [System.IO.FileInfo] Backup([string]$Path) {
        $this.InvokeSqlNoResult("VACUUM INTO '$Path';")
        return Get-Item -LiteralPath $Path
    }
    [string] ToString() {
        return 'Database,Tables {0} ({1})' -f ($this.GetTables().Keys -join ','), $this.FileSize
    }
}

# .SYNOPSIS
#  Represents an index in a database table
class Index {
    [string] $Name
    [bool] $Unique
    [bool] $IsMultiColumn
    # column contains references to database and table
    [DatabaseField[]]$Column

    Index([string]$Name, [bool]$Unique, [DatabaseField[]]$Column) {
        $this.Name = $Name
        $this.Unique = $Unique
        $this.Column = $Column
        $this.IsMultiColumn = $Column.Count -gt 1
    }
    [void] DropIndex() {
        $sql = "Drop Index If Exists $($this.Name)"
        $this.Column.Table.Database.InvokeSqlNoResult($sql)
    }
    [string] ToString() {
        return '{0} on {1} ({2}, {3})' -f $this.Name, $this.Column.Name, $this.Column.Type, ('NONUNIQUE', 'UNIQUE')[$this.Unique]
    }
}

# .SYNOPSIS
#  Represents a database table
class Table {
    [Database] $Database
    [string] $Name
    [bool] $HasErrors
    [string] $RowError
    [System.Data.DataRowState] $RowState
    [string] $Definition

    # The constructor takes the database plus the original datarow with the
    # Table infos returned by the database
    Table([Database]$Database, [System.Data.DataRow]$TableInfo) {
        # Translate the original datarow object to the Table object properties:
        $this.Name = $TableInfo.Name
        $this.Definition = $TableInfo.Sql
        $this.Database = $Database
        $this.RowError = $TableInfo.RowError
        $this.RowState = $TableInfo.RowState
        $this.HasErrors = $TableInfo.HasErrors

        # .NOTES
        # Count(*) takes a long time on large tables, we output the number of rows
        # this is a good approximation but will not take into account deleted records
        # as the row id is constantly increasing
        $this | Add-Member -MemberType ScriptProperty -Name Count -Value {
            # $this.Database.InvokeSql("Select Count(*) from $($this.Name)") | Select-Object -ExpandProperty 'Count(*)'
            $count = $this.Database.InvokeSql("SELECT MAX(_ROWID_) FROM $($this.Name) LIMIT 1;") | Select-Object -ExpandProperty 'MAX(_ROWID_)'
            if ($Count -eq [System.DBNull]::Value) {
                'EMPTY'
            } else {
                $count
            }
        }
    }
    # Get the column names and types of this table
    # Similar approach as GetTables() in regards to returning an ordered hashtable
    [System.Collections.Specialized.OrderedDictionary] GetFields() {
        # get the detailed table information for this table
        $sql = 'PRAGMA table_info({0});' -f $this.Name
        # and translate each returned record into a Column object
        $hash = [Ordered]@{}
        foreach ($column in $this.Database.InvokeSql($sql)) {
            $hash[$column.Name] = [DatabaseField]::new($this, $column)
        }
        return $hash
    }
    [string] ToString() {
        return '{0,-6}:{1}' -f $this.Count, ($this.GetFields().Keys -join ',')
    }

    [int] GetRecordCount() {
        return ($this.Database.InvokeSql("Select Count(*) from $($this.Name)") | Select-Object -ExpandProperty 'Count(*)') -as [int]
    }

    # delete the table from the database
    [void] DropTable() {
        # WARNING: the table and all of its data is immediately deleted
        $SQL = "Drop Table $($this.Name);"
        $this.Database.InvokeSQL($SQL)
    }

    # get indices
    [Index[]] GetIndexes() {
        $tableName = $this.Name
        $columns = $this.GetFields()

        $sql = "PRAGMA index_list('$tableName')"
        $indexes = foreach ($index in $this.Database.InvokeSql($sql)) {
            $indexName = $index.Name
            [bool]$unique = $index.Unique
            $columnName = $this.Database.InvokeSql("PRAGMA index_info('$indexName')").name
            [Index]::new($indexName, $unique, $columns[$columnName])
        }
        return $indexes
    }

    [System.Data.DataRow[]] GetData() {
        # dump all table data
        $sql = "select * from {0}" -f $this.Name
        return $this.Database.InvokeSql($sql)
    }

    [System.Data.DataRow[]] GetData([string]$Filter) {
        # dump all table data
        $sql = "select * from {0} where $Filter" -f $this.Name
        return $this.Database.InvokeSql($sql)
    }

    [System.Data.DataRow[]] GetData([string]$Filter, [bool]$CaseSensitive) {
        # dump all table data
        $sql = "select * from {0} where $Filter" -f $this.Name
        return $this.Database.InvokeSql($sql, $CaseSensitive)
    }
    # TODO: add method to query this table
}

function Get-DataPath {
    [CmdletBinding()]
    [OutputType([System.IO.DirectoryInfo])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$appName,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]$SubdirName,

        [switch]$DontCreate
    )

    process {
        $_Host_OS = Get-HostOs
        $dataPath = if ($_Host_OS -eq 'Windows') {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine($Env:HOME, "AppData", "Roaming", $appName, $SubdirName))
        } elseif ($_Host_OS -in ('Linux', 'MacOs')) {
            [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
        } elseif ($_Host_OS -eq 'Unknown') {
            try {
                [System.IO.DirectoryInfo]::new([IO.Path]::Combine((($env:PSModulePath -split [IO.Path]::PathSeparator)[0] | Split-Path | Split-Path), $appName, $SubdirName))
            } catch {
                Write-Warning "Could not resolve chat data path"
                Write-Warning "HostOS = '$_Host_OS'. Could not resolve data path."
                [System.IO.Directory]::CreateTempSubdirectory(($SubdirName + 'Data-'))
            }
        } else {
            throw [InvalidOperationException]::new('Could not resolve data path. Get-HostOS FAILED!')
        }
        if (!$dataPath.Exists -and !$DontCreate.IsPresent) { New-Directory -Path $dataPath.FullName }
        return $dataPath
    }
}

function New-Database {
    #  .SYNOPSIS
    #   Creates a database object (A representation a SQLite database).
    # .DESCRIPTION
    #   If the database (.db) file already exists, then it opens that instead.
    #   To create new tables and store new data in the database, use Import-Database and
    #   supply the database object to this function
    # .EXAMPLE
    #   $db = New-Database
    #   returns a memory-based database
    # .EXAMPLE
    #   $db = New-Database -Path $env:temp\test.db
    #   Opens the file-based database. If the file does not exist, a new database file is created
    # .EXAMPLE
    #   $db = Open-Database -Path c:\data\database1.db
    #   $db.GetTables()
    #   opens the file-based database and lists the tables found in the database
    # .EXAMPLE
    #   $db = New-Database -Path c:\data\database1.db
    #   $db.InvokeSQL('Select * from customers')
    #   runs the SQL statement and queries all records from the table "customers".
    #   The table "customers" must exist.
    [CmdletBinding()]
    [Alias('Open-Database')]
    [OutputType([Database])]
    param (
        # Path to the database file. If the file does not yet exist, it will be created
        # this parameter defaults to ":memory:" which creates a memory-based database
        # memory-based databases are very fast but the data is not permanently stored
        # once the database is closed or PowerShell ends, the memory-based database is
        # deleted
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$Path = ':memory:'
    )
    begin {
        if ('Internal.Helper' -as 'type' -isnot [type]) { Import-SQLiteDlls }
    }
    process {
        return New-Object Database($Path)
    }
}

function Import-Database {
    # .SYNOPSIS
    #   Imports new data to a database table. Data can be added to existing or new tables.
    # .DESCRIPTION
    #   Import-Database automatically examines incoming objects and creates the
    #   table definition required to store these objects. The first object received
    #   by Import-Database determines the table layout.
    #   If the specified table already exists, Import-Database checks whether the existing
    #   table has fields for all object properties.
    # .EXAMPLE
    #   $db = New-Database
    #   Get-Service | Import-Database -Database $db -Table Services
    #   $db.InvokeSql('Select * From Services') | Out-GridView
    #   creates a memory-based database, then pipes all services into the database
    #   and stores them in a new table called "Services"
    #   Next,the table content is queried via Sql and the result displays in a gridview
    #   Note that the database content is lost once PowerShell ends
    # .EXAMPLE
    #   $db = New-Database -Path $env:temp\temp.db
    #   Get-Service | Import-Database -Database $db -Table Services
    #   $db.InvokeSql('Select * From Services') | Out-GridView
    #   opens the file-based database in $env:temp\temp.db, and if the file does not exist,
    #   a new file is created. All services are piped into the database
    #   and stored in a table called "Services".
    #   If the table "Services" exists already, the data is appended to the table, else
    #   a new table is created.
    #   Next,the table content is queried via Sql and the result displays in a gridview
    #   Since the database is file-based, all content imported to the database is stored
    #   In the file specified.
    # .EXAMPLE
    #   $db = New-Database -Path $env:temp\temp.db
    #   $db.QueryTimeout = 6000
    #   Get-ChildItem -Path c:\ -Recurse -ErrorAction SilentlyContinue -File | Import-Database -Database $db -Table Files
    #   Writes all files on drive C:\ to table "Files". Since this operation may take a long
    #   time,the database "QueryTimeout" property is set to 6000 seconds (100 min)
    #   A better way is to split up data insertion into multiple chunks that execute
    #   faster. This can be achieved via -TransactionSet. This parameter specifies the
    #   chunk size (number of objects) that should be imported before a new transaction
    #   starts.
    # .EXAMPLE
    #   $db = New-Database -Path $home\Documents\myDatabase.db
    #   Get-ChildItem -Path $home -Recurse -File -ErrorAction SilentlyContinue | Import-Database -Database $db -Table FileList -UseUnsafePerformanceTricks -LockDatabase -TransactionSet 10000
    #   $db.InvokeSql('Select * From FileList Where Extension=".log" Order By "Length"') | Out-GridView
    #   A file-based database is opened. If the file does not yet exist, it is created.
    #   Next,all files from the current user profile are collected by Get-ChildItem,
    #   and written to the database table "FileList". If the table exists, the data is
    #   appended,else the table is created.
    #   Next,the table "FileList" is queried by Sql, and all files with extension ".log"
    #   display in a gridview ordered by file size
    #   To improve performance, Import-Database temporarily locks the database and turns off
    #   Get-database features that normally improve robustness in the event of a crash.
    #   By turning off these features, performance is increased considerably at the expense
    #   of data corruption.
    # .NOTES
    #   Use New-Database to get the database first.
    [CmdletBinding()]
    param (
        # The data to be written to the database table
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [Object[]]$InputObject,

        # Database object returned by New-Database
        [Parameter(Mandatory = $true, Position = 1)]
        [Database]$Database,

        # Name of table to receive the data. If the table exists, the data appends the table.
        # Else, a new table is created based on the properties of the first received object.
        [Parameter(Mandatory = $true, Position = 2)]
        [String]$TableName,

        # to increase performance, transactions are used. To increase robustness and
        # receive progress information, the transaction can be limited to any number of
        # new objects. Once the number of objects have been written to the database table,
        # the transaction is committed, status information and stats are returned,
        # and a new transaction starts.
        # commit data to database at least after these many of new data sets
        [Parameter(Mandatory = $false)]
        [int]$TransactionSet = 20000,

        # temporarily turns off cost-intensive security features to increase speed
        # at the expense of a higher risk of data corruption if the database crashes
        # during the operation
        # speeds up data insertion at the expense of protection against data corruption in case of crashes or unexpected failures
        [Parameter(Mandatory = $false)]
        [Switch]$UseUnsafePerformanceTricks,

        # temporarily locks access to the database file to increase speed.
        # While the database file is locked, noone else can access the database.
        [Parameter(Mandatory = $false)]
        [Switch]$LockDatabase,

        # takes the first object and defines the table. Does not add any data
        # this can be used to predefine a new table layout based on a sample
        # object
        [Parameter(Mandatory = $false)]
        [Switch]$DefineTableOnly,

        # when the type of a field does not match the type of an object property,
        # the type is autoconverted to the existing field type
        [Parameter(Mandatory = $false)]
        [Switch]$AllowTypeConversion,

        # returns the table object
        [Parameter(Mandatory = $false)]
        [Switch]$PassThru
    )

    begin {
        # count the incoming objects
        $dataSetCount = 0
        # the first object is examined to figure out the table layout
        $first = $true
        #region Performance Options
        # if performance options were specified, save the current values
        # so they can be restored later, and apply the changes
        $oldSetting1 = $oldSetting2 = $null
        if ($UseUnsafePerformanceTricks) {
            $oldSetting1 = $database.EnableUnsafePerformanceMode
            $database.EnableUnsafePerformanceMode = $true
        }
        if ($LockDatabase) {
            $oldSetting2 = $database.LockDatabase
            $database.LockDatabase = $true
        }
        # make sure the database can store the maximum amount of data
        $database.InvokeSqlNoResult('PRAGMA PAGE_SIZE=65535')
    }

    process {
        if ('Internal.Helper' -as 'type' -isnot [type]) { Import-SQLiteDlls }
        # process any object that is received either via the pipeline
        # or via an array
        foreach ($object in $InputObject) {
            #region process first incoming object
            # if this is the first data item, we need to find out the
            # column definition
            if ($first) {
                $first = $false
                $wmiDatePattern = '^\d{14}\.\d{6}\+\d{3}$'
                # get the requirements for this object
                $Fields = $database.GetFieldNamesFromObject($object)
                # keep record of target field types so when data is inserted,
                # it can be converted to the desired type if required
                $fieldTypes = @{}
                $fields | ForEach-Object { $fieldTypes[$_.Name] = $_.Type }
                #region get or create table
                # check for the destination table inside the database
                $table = $database.GetTable($TableName)
                if ($null -eq $table) {
                    # if it does not yet exist, create it based on the requirements
                    # of the first object
                    # we use the "object field separator" in $ofs to quickly
                    # create the sql field string. $Fields contains an array of
                    # Column objects. Their ToString() method displays field name and
                    # field type separated by a space. The OFS turns the array into
                    # a string and uses the string specified in $ofs to concatenate
                    # the array elements, thus a comma-separated list is created:
                    $ofs = ','
                    $fieldstring = "$Fields".TrimEnd(',')
                    # create the table based on the fieldstring:
                    $query = 'CREATE TABLE {0} ({1})' -f $TableName, $fieldString
                    $Database.InvokeSqlNoResult($query)
                    # keep an array of field names that is later used to compile the
                    # insertion statement
                    $columnTable = $fields.Name
                    # set $foundAny to $true because ALL fields are matching since we created
                    # the table based on the object
                    $foundAny = $true
                } else {
                    # if the table is present already, check whether the fields in the
                    # existing table match the required fields
                    # for this, get the column names from the existing table
                    $columns = $table.GetFields()
                    # test whether columns match
                    $foundAny = $false
                    $missing = foreach ($field in $fields) {
                        # if the field exists...
                        if ($columns.Contains($field.Name)) {
                            $foundAny = $true
                            # ...check the field type. Does it match as well?
                            $existingType = $columns[$field.Name].Type
                            if ($existingType -ne $field.Type) {
                                $message = 'Field {0} is of type {1} but you are adding type {2}.' -f $Field.Name, $existingType, $field.Type
                                if ($AllowTypeConversion) {
                                    Write-Warning $message
                                    # update the field type because now the object property
                                    # type does not match the table field type
                                    $fieldTypes[$field.Name] = $existingType
                                } else {
                                    # if the field exists but the field type is different,
                                    # there is no way to fix this, and an exception is thrown
                                    throw [System.InvalidOperationException]::new($message)
                                }
                            }
                        } else {
                            # if the field does not exist, it is added to the $missing list
                            $field
                        }
                    }
                    $missing | ForEach-Object {
                        Write-Warning "Table '$($Table.Name)' has no field '$($_.Name)'."
                    }
                    if ($missing.Count -gt 0) {
                        Write-Warning "Consider adding data to a new table with a more appropriate design, or adding missing fields to the table."
                    }
                    if (!$foundAny) {
                        throw "There are NO matching fields in table '$($table.Name)'. Import to a new table, or use an existing table that matches the object type."
                    }
                    # keep an array of field names that is later used to compile the
                    # insertion statement
                    $columnTable = $columns.Keys
                }
                #endregion get or create table
                #region abort pipeline if table prototyping is active
                if ($DefineTableOnly.isPresent -or !$foundAny) {
                    # abort pipeline
                    $p = { Select-Object -First 1 }.GetSteppablePipeline()
                    $p.Begin($true)
                    $p.Process(1)
                }
                #endregion abort pipeline if table prototyping is active

                #region precompile insertion command
                # adding new data via an INSERT INTO sql statement per object
                # would be very slow for large numbers of objects
                # a much faster way uses a precompiled insertion command
                # which is created now:

                # create a comma-separated list of field names
                $fieldNames = '"' + ($columnTable -join '","') + '"'
                # create a comma-separated list of variable names which really are
                # field names prepended with "$"
                $variableNames = foreach ($_ in $columnTable) { '${0}' -f $_ }
                $variableNamesString = $variableNames -join ','

                # precompile the insertion command
                # the insertion command is a default INSERT INTO sql statement except
                # that it does not contain the actual values but instead
                # variable names:
                $command = $database.Connection.CreateCommand()
                $command.CommandText = 'INSERT INTO {0}({1}) VALUES({2});' -f $TableName, $fieldNames, $variableNamesString

                # to be able to later replace the variables with the actual data,
                # parameters need to be created for each variable:
                $parameters = $variableNames | ForEach-Object {
                    # create a parameter
                    $parameter = $command.CreateParameter()
                    $parameter.ParameterName = $_

                    # add the parameter to the command
                    $null = $command.Parameters.Add($parameter)
                    #endregion precompile insertion command

                    # add a noteproperty so we can attach the original property name (less "$") for
                    # easy retrieval later when the object properties are queried:
                    $realName = $_.Substring(1)
                    $parameter | Add-Member -MemberType NoteProperty -Name RealName -Value $realName -PassThru | Add-Member -MemberType NoteProperty -Name RealType -Value $fieldTypes[$realName] -PassThru
                }

                # bulk-insert groups of objects to improve performance.
                # This is done by starting a transaction.
                # While the transaction is active, no data is written to the
                # table. Only when the transaction is committed, the entire collected data
                # is written.
                # use a transaction to insert multiple data sets in one operation
                $transaction = $database.Connection.BeginTransaction()

                # remember start time for stats
                $start = $baseStart = Get-Date
            }
            #endregion process first incoming object

            # the remaining code is executed for any object received

            #region add one object to the table
            # increment the counter
            $dataSetCount++

            # submit the actual object property values for each parameter
            # we added to the INSERT INTO command
            foreach ($parameter in $parameters) {
                # get the property name only
                $propName = $parameter.RealName
                $value = $object.$propName

                # if the value is an array, turn the array into a comma-separated
                # string
                if ($value -is [Array]) {
                    $parameter.Value = $value -join ','
                } else {
                    # if the data type is DateTime, we must make sure the value is
                    # actually a suitable datetime because SQLite will store it anyway,
                    # causing problems when the data is queried later and cannot be converted
                    if ($parameter.RealType -eq 'DateTime') {
                        $dateTimeValue = $value -as [DateTime]
                        if ($null -ne $dateTimeValue) {
                            $value = $dateTimeValue.ToString('yyyy-MM-dd HH:mm:ss')
                        } elseif ($value -match $wmiDatePattern) {
                            $value = [System.Management.ManagementDateTimeConverter]::ToDateTime($value).ToString('yyyy-MM-dd HH:mm:ss')
                        } else {
                            $value = $null
                        }
                    }
                    $parameter.Value = $value
                }
            }

            # add the command to the transaction
            $null = $command.ExecuteNonQuery()
            #endregion add one object to the table

            # by default, the transaction is committed only when all objects are
            # received. For large numbers of objects, a transactionset size can be
            # specified. When the specified number of objects are received, the
            # current transaction is committed, and the caller gets back some stats.
            if ($TransactionSet -gt 0 -and ($dataSetCount % $TransactionSet -eq 0)) {
                $chunkTimePassed = ((Get-Date) - $start).TotalSeconds
                $timePassed = ((Get-Date) - $baseStart).TotalMinutes
                $size = '{0:n2} MB' -f ([IO.FileInfo]::new($Database._path).Length / 1MB)

                $info = [PSCustomObject]@{
                    Processed = $dataSetCount
                    ChunkTime = '{0:n1} sec.' -f $chunkTimePassed
                    TotalTime = '{0:n1} min.' -f $timePassed
                    FileSize  = $size
                    FilePath  = $Database._path
                }
                $start = Get-Date
                Write-Warning -Message ($info | Out-String)
                # commit the current transaction
                $transaction.Commit()
                # start a new transaction
                $Transaction = $database.Connection.BeginTransaction()
                $dataSetCount = 0
            }
        }
    }

    end {
        # commit pending transaction only if new records have been added
        if ($dataSetCount -gt 0) {
            $transaction.Commit()
        }
        #region reset temporary database options
        # reset performance settings to default
        if ($UseUnsafePerformanceTricks) {
            $Database.EnableUnsafePerformanceMode = $oldSetting1
        }
        if ($LockDatabase) {
            $database.LockDatabase = $oldSetting2
        }
        #endregion reset temporary database options

        if ($PassThru) {
            $Database.GetTable($TableName)
        }
    }
}

function New-RecordMap {
    [CmdletBinding()]
    [OutputType([RecordMap])]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [AllowNull()][Alias('ht')]
        [hashtable[]]$hashtable
    )
    begin {
        class RecordMap {
            hidden [uri] $Remote # usually a gist uri
            hidden [string] $File
            hidden [bool] $IsSynchronized
            [datetime] $LastWriteTime = [datetime]::Now
            RecordMap() { $this._init() }
            RecordMap([hashtable[]]$array) {
                $this.Add($array); $this._init()
            }
            hidden [void] _init() {
                $this | Add-Member -MemberType ScriptProperty -Name 'Properties' -Value {
                    return ($this | Get-Member -Type *Property).Name.Where({ $_ -notin ('Count', 'Properties', 'IsSynchronized') })
                } -SecondValue {
                    Throw [System.InvalidOperationException]::new("'Properties' is a readOnly property!")
                } -Force
                $this.PsObject.properties.add([psscriptproperty]::new('Count', [scriptblock]::Create({ $this.Properties.count })))
            }
            [void] Import([uri]$raw_uri, [Object]$session) {
                try {
                    Push-Stack -class "ArgonCage"; $pass = $null;
                    Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([RecordMap]::GetSessionKey("Paste/write a Password to decrypt configs", $session, 'configrw'))
                    $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($(Invoke-WebRequest $raw_uri -Verbose:$false).Content), $pass)))
                    $this.Set([hashtable[]]$_ob.Properties.Name.ForEach({ @{ $_ = $_ob.$_ } }))
                } catch {
                    throw $_
                } finally {
                    Remove-Variable Pass -Force -ErrorAction SilentlyContinue
                }
            }
            [void] Import([String]$FilePath, [PsObject]$session) {
                Write-Host "$(Show-Stack) Import records: $FilePath ..." -f Green
                $this.Set([RecordMap]::Read($FilePath, $session))
                Write-Host "$(Show-Stack) Import records Complete" -f Green
            }
            [void] Upload() {
                if ([string]::IsNullOrWhiteSpace($this.Remote)) { throw [System.ArgumentException]::new('remote') }
                # $gisturi = 'https://gist.github.com/' + $this.Remote.Segments[2] + $this.Remote.Segments[2].replace('/', '')
                # Update-Gist -uri $gisturi -c $content
            }
            [void] Add([hashtable]$table) {
                [ValidateNotNullOrEmpty()][hashtable]$table = $table
                $Keys = $table.Keys | Where-Object { !$this.HasNoteProperty($_) -and ($_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType') }
                foreach ($key in $Keys) {
                    if ($key -notin ('File', 'Remote', 'LastWriteTime')) {
                        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key]
                    } else {
                        $this.$key = $table[$key]
                    }
                }
            }
            [void] Add([hashtable[]]$items) {
                foreach ($item in $items) { $this.Add($item) }
            }
            [void] Add([string]$key, [System.Object]$value) {
                [ValidateNotNullOrEmpty()][string]$key = $key
                if (!$this.HasNoteProperty($key)) {
                    $htab = [hashtable]::new(); $htab.Add($key, $value); $this.Add($htab)
                } else {
                    Write-Warning "Record.Add() Skipped $Key. Key already exists."
                }
            }
            [void] Add([System.Collections.Generic.List[hashtable]]$items) {
                foreach ($item in $items) { $this.Add($item) }
            }
            [void] Set([string]$key, [System.Object]$value) {
                $htab = [hashtable]::new(); $htab.Add($key, $value)
                $this.Set($htab)
            }
            [void] Set([hashtable[]]$items) {
                foreach ($item in $items) { $this.Set($item) }
            }
            [void] Set([hashtable]$table) {
                [ValidateNotNullOrEmpty()][hashtable]$table = $table
                $Keys = $table.Keys | Where-Object { $_.GetType().FullName -eq 'System.String' -or $_.GetType().BaseType.FullName -eq 'System.ValueType' } | Sort-Object -Unique
                foreach ($key in $Keys) {
                    if (!$this.PsObject.Properties.Name.Contains($key)) {
                        $this | Add-Member -MemberType NoteProperty -Name $key -Value $table[$key] -Force
                    } else {
                        $this.$key = $table[$key]
                    }
                }
            }
            [void] Set([System.Collections.Specialized.OrderedDictionary]$dict) {
                $dict.Keys.Foreach({ $this.Set($_, $dict["$_"]) });
            }
            [bool] HasNoteProperty([object]$Name) {
                [ValidateNotNullOrEmpty()][string]$Name = $($Name -as 'string')
                return (($this | Get-Member -Type NoteProperty | Select-Object -ExpandProperty name) -contains "$Name")
            }
            static hidden [SecureString] GetSessionKey([string]$message, [PsObject]$session, [string]$Name) {
                return $session.GetSessionKey($Name, [PSCustomObject]@{
                        caller = Show-Stack
                        prompt = $message
                    }
                )
            }
            [array] ToArray() {
                $array = @(); $props = $this | Get-Member -MemberType NoteProperty
                if ($null -eq $props) { return @() }
                $props.name | ForEach-Object { $array += @{ $_ = $this.$_ } }
                return $array
            }
            [string] ToJson() {
                return [string]($this | Select-Object -ExcludeProperty count | ConvertTo-Json -Depth 3)
            }
            [System.Collections.Specialized.OrderedDictionary] ToOrdered() {
                $dict = [System.Collections.Specialized.OrderedDictionary]::new(); $Keys = $this.PsObject.Properties.Where({ $_.Membertype -like "*Property" }).Name
                if ($Keys.Count -gt 0) {
                    $Keys | ForEach-Object { [void]$dict.Add($_, $this."$_") }
                }
                return $dict
            }
            static [hashtable[]] Read([string]$FilePath, $session) {
                Push-Stack -class "ArgonCage"; $pass = $null; $cfg = $null; $FilePath = (AesGCM)::GetResolvedPath($FilePath);
                if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
                Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $([RecordMap]::GetSessionKey("Paste/write a Password to decrypt configs", $session, 'configrw'))
                $txt = [IO.File]::ReadAllText($FilePath)
                $_ob = (xconvert)::Deserialize((xconvert)::ToDeCompressed((AesGCM)::Decrypt((Base85)::Decode($txt), $pass)))
                $cfg = [hashtable[]]$_ob.PsObject.Properties.Name.Where({ $_ -notin ('Count', 'Properties', 'IsSynchronized') }).ForEach({ @{ $_ = $_ob.$_ } })
                return $cfg
            }
            [hashtable[]] Edit($session) {
                $result = $this.Edit($this.File, $session)
                $this.Set($result); $this.Save($session)
                return $result
            }
            [hashtable[]] Edit([string]$FilePath, [Object]$session) {
                $result = @(); $private:config_ob = $null; $fswatcher = $null; $process = $null;
                $FilePath = (AesGCM)::GetResolvedPath($FilePath);
                if ([IO.File]::Exists($FilePath)) { if ([string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($FilePath).Trim())) { throw [System.Exception]::new("File is empty: $FilePath") } } else { throw [System.IO.FileNotFoundException]::new("File not found: $FilePath") }
                $OutFile = [IO.FileInfo][IO.Path]::GetTempFileName()
                $UseVerbose = [bool]$((Get-Variable verbosePreference -ValueOnly) -eq "continue")
                try {
                    Block-AllOutboundConnections
                    if ($UseVerbose) { "[+] Edit Config started .." | Write-Host -f Magenta }
                    $parsed_content = [RecordMap]::Read($FilePath, $session);
                    [ValidateNotNullOrEmpty()][hashtable[]]$parsed_content = $parsed_content
                    $parsed_content | ConvertTo-Json | Out-File $OutFile.FullName -Encoding utf8BOM
                    Set-Variable -Name OutFile -Value $(Rename-Item $outFile.FullName -NewName ($outFile.BaseName + '.json') -PassThru)
                    $process = [System.Diagnostics.Process]::new()
                    $process.StartInfo.FileName = 'nvim'
                    $process.StartInfo.Arguments = $outFile.FullName
                    $process.StartInfo.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Maximized
                    $process.Start(); $fswatcher = Start-FsWatcher -File $outFile.FullName -OnComplete ([scriptblock]::Create("Stop-Process -Id $($process.Id) -Force"));
                    if ($null -eq $fswatcher) { Write-Warning "Failed to start FileMonitor"; Write-Host "Waiting nvim process to exit..." $process.WaitForExit() }
                    $private:config_ob = [IO.FILE]::ReadAllText($outFile.FullName) | ConvertFrom-Json
                } finally {
                    Unblock-AllOutboundConnections
                    if ($fswatcher) { $fswatcher.Dispose() }
                    if ($process) {
                        "[+] Neovim process {0} successfully" -f $(if (!$process.HasExited) {
                                $process.Kill($true)
                                "closed"
                            } else {
                                "exited"
                            }
                        ) | Write-Host -f Green
                        $process.Close()
                        $process.Dispose()
                    }
                    Remove-Item $outFile.FullName -Force
                    Set-Variable -Name (Get-FMLogvariableName) -Scope Global -Value (Get-FileMonitorLog) | Out-Null
                    if ($UseVerbose) { "[+] FileMonitor Log saved in variable: `$$(Get-FMLogvariableName)" | Write-Host -f Magenta }
                    if ($null -ne $config_ob) { $result = $config_ob.ForEach({ (xconvert)::ToHashTable($_) }) }
                    if ($UseVerbose) { "[+] Edit Config completed." | Write-Host -f Magenta }
                }
                return $result
            }
            [void] Save($session) {
                try {
                    [ValidateNotNullOrEmpty()][Object]$session = $session
                    $cllr = Show-Stack; [ValidateNotNullOrEmpty()][string]$cllr = $cllr
                    $pass = $null; Write-Host "$cllr Saving records to file: $($this.File) ..." -f Blue
                    Set-Variable -Name pass -Scope Local -Visibility Private -Option Private -Value $($session.GetSessionKey('configrw', [PSCustomObject]@{
                                caller = $cllr
                                prompt = "Paste/write a Password to encrypt configs"
                            }
                        )
                    ); [ValidateNotNullOrEmpty()][securestring]$pass = $pass
                    $this.LastWriteTime = [datetime]::Now; [IO.File]::WriteAllText($this.File, (Base85)::Encode((AesGCM)::Encrypt((xconvert)::ToCompressed($this.ToByte()), $pass)), [System.Text.Encoding]::UTF8)
                    Write-Host "$cllr Saving records " -f Blue -NoNewline; Write-Host "Completed." -f Green
                } catch {
                    throw $_
                } finally {
                    Remove-Variable Pass -Force -ErrorAction SilentlyContinue
                }
            }
            [byte[]] ToByte() {
                return (xconvert)::Serialize($this)
            }
            [string] ToString() {
                $r = $this.ToArray(); $s = ''
                $shortnr = [scriptblock]::Create({
                        param([string]$str, [int]$MaxLength)
                        while ($str.Length -gt $MaxLength) {
                            $str = $str.Substring(0, [Math]::Floor(($str.Length * 4 / 5)))
                        }
                        return $str
                    }
                )
                if ($r.Count -gt 1) {
                    $b = $r[0]; $e = $r[-1]
                    $0 = $shortnr.Invoke("{'$($b.Keys)' = '$($b.values.ToString())'}", 40)
                    $1 = $shortnr.Invoke("{'$($e.Keys)' = '$($e.values.ToString())'}", 40)
                    $s = "@($0 ... $1)"
                } elseif ($r.count -eq 1) {
                    $0 = $shortnr.Invoke("{'$($r[0].Keys)' = '$($r[0].values.ToString())'}", 40)
                    $s = "@($0)"
                } else {
                    $s = '@()'
                }
                return $s
            }
        }
    }
    end {
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('hashtable')) {
            if ($null -ne $hashtable) {
                return [RecordMap]::New($hashtable)
            }
        }
        return [RecordMap]::New()
    }
}
function Get-HostOs() {
    process {
        #TODO: refactor so that it returns one of these: [Enum]::GetNames([System.PlatformID])
        return $(
            if ($(Get-Variable IsWindows -Value)) {
                "Windows"
            } elseif ($(Get-Variable IsLinux -Value)) {
                "Linux"
            } elseif ($(Get-Variable IsMacOS -Value)) {
                "macOS"
            } else {
                "UNKNOWN"
            }
        )
    }
}

function New-Directory {
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Path
    )
    process {
        [ValidateNotNullOrEmpty()][System.IO.DirectoryInfo]$Path = $Path
        $nF = @(); $p = $Path; while (!$p.Exists) { $nF += $p; $p = $p.Parent }
        [Array]::Reverse($nF); $nF | ForEach-Object { $_.Create(); Write-Debug "Created $_" }
    }
}

function Dump_chromepass {
    [CmdletBinding()]
    param ()
    process {
        Add-Type -AssemblyName System.Security
        # default path to Chrome user passwords database:
        $Path = [IO.Path]::Combine("$env:LOCALAPPDATA", "Google", "Chrome", "User Data", "Default", "Login Data")
        if (![IO.File]::Exists($Path)) {
            Write-Warning "No Chrome Database found."
            return
        }
        # copy the database (the original file is locked while Chrome is running):
        $Destination = [IO.Path]::Combine($env:temp, "chrome_data.db")
        Copy-Item -Path $Path -Destination $Destination
        # query to retrieve the cached passwords:
        $sql = "SELECT action_url, username_value, password_value FROM logins"
        # rename column headers:
        $url = @{N = 'Url'; E = { $_.action_url } }
        $username = @{N = 'Username'; E = { $_.username_value } }
        $password = @{N = 'Password'; E = { [System.Text.Encoding]::Default.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($_.password_value, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)) } }
        $db = New-Database -Path $Destination
        $db.InvokeSql($sql) | Select-Object $url, $username, $password
    }
}

function Initialize-SQLiteDB {
    [CmdletBinding()]
    param ()
    begin {
        $Param_TableName_ArgCompleter = [scriptblock]::Create({
                param (
                    $CommandName,
                    $ParameterName,
                    $WordToComplete,
                    $CommandAst,
                    $params
                )
                if ($params.ContainsKey('Database')) {
                    $db = $params['Database'] -as [Database]
                    if ($null -ne $db) {
                        try {
                            $tables = $db.GetTables()
                            $($tables.Keys -like "$WordToComplete*").ForEach({ [System.Management.Automation.CompletionResult]::new($_, $_, [System.Management.Automation.CompletionResultType]::ParameterValue, ("$($tables[$_])".Trim() | Out-String)) })
                        } catch { $null }
                    }
                }
            }
        )
        $Param_Database_ArgCompleter = [scriptblock]::Create({
                param (
                    $CommandName,
                    $ParameterName,
                    $WordToComplete,
                    $CommandAst,
                    $params
                )
                Get-Variable | Where-Object { $_.Value -is [Database] } | ForEach-Object {
                    $value = '${0}' -f $_.Name
                    [System.Management.Automation.CompletionResult]::new($value, $value, [System.Management.Automation.CompletionResultType]::Variable, ("$($_.Value)".Trim() | Out-String))
                }
            }
        )
    }
    process {
        if (($VerbosePreference -eq "Continue")) { Write-Host "VERBOSE: Initializing SQLiteDB ..." -f Green }
        Import-SQLiteDlls
        Register-ArgumentCompleter -ParameterName TableName -CommandName Import-Database -ScriptBlock $Param_TableName_ArgCompleter
        Register-ArgumentCompleter -ParameterName Database -CommandName Import-Database -ScriptBlock $Param_Database_ArgCompleter
    }
}

Initialize-SQLiteDB
Export-ModuleMember -Function '*' -Variable '*' -Cmdlet '*' -Alias '*' -Verbose:($VerbosePreference -eq "Continue")