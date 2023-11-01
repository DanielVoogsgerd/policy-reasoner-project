//  SPEC.rs
//    by Lut99
//
//  Created:
//    27 Oct 2023, 15:56:55
//  Last edited:
//    31 Oct 2023, 15:39:22
//  Auto updated?
//    Yes
//
//  Description:
//!   Defines the checker workflow itself.
//

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use brane_ast::locations::Location;
use brane_ast::MergeStrategy;
use enum_debug::EnumDebug;
use specifications::version::Version;


/***** HELPER MACROS *****/
/// Implements all the boolean checks for the [`NextElem`]-variants.
///
/// # Variants
/// - `next_elem_checks_impl($name:ident)`
///   - `$name`: The name of the type for which to implement them.
/// - `next_elem_checks_impl($($l:lifetime),+), $name:ident)`
///   - `$l`: A list of lifetimes for this type.
///   - `$name`: The name of the type for which to implement them.
macro_rules! next_elem_checks_impl {
    ($name:ident) => {
        impl $name {
            next_elem_checks_impl!(body_impl $name);
        }
    };
    ($($l:lifetime),+, $name:ident) => {
        impl<$($l),+> $name<$($l),+> {
            next_elem_checks_impl!(body_impl $name);
        }
    };



    // Private
    (body_impl $name:ident) => {
        #[doc = concat!("Checks if there is a next node or not.\n\nAlias for `Self::is_elem()`.\n\n# Returns\nTrue if we are [Self::Elem](", stringify!($name), "::Elem), or false otherwise.")]
        #[inline]
        pub fn is_some(&self) -> bool { self.is_elem() }
        #[doc = concat!("Checks if a terminator has been reached or not.\n\n# Returns\nTrue if we are [Self::Next](", stringify!($name), "::Next) or [Self::Stop](", stringify!($name), "::Stop), or false otherwise.")]
        #[inline]
        pub fn is_term(&self) -> bool { self.is_next() || self.is_return() || self.is_stop() }

        #[doc = concat!("Checks if there is a next node or not.\n\n# Returns\nTrue if we are [Self::Elem](", stringify!($name), "::Elem), or false otherwise.")]
        #[inline]
        pub fn is_elem(&self) -> bool { matches!(self, Self::Elem(_)) }
        #[doc = concat!("Checks if a `Next`-terminator has been reached.\n\n# Returns\nTrue if we are [Self::Next](", stringify!($name), "::Next), or false otherwise.")]
        #[inline]
        pub fn is_next(&self) -> bool { matches!(self, Self::Next) }
        #[doc = concat!("Checks if a `Return`-terminator has been reached.\n\n# Returns\nTrue if we are [Self::Return](", stringify!($name), "::Return), or false otherwise.")]
        #[inline]
        pub fn is_return(&self) -> bool { matches!(self, Self::Return) }
        #[doc = concat!("Checks if a `Stop`-terminator has been reached.\n\n# Returns\nTrue if we are [Self::Stop](", stringify!($name), "::Stop), or false otherwise.")]
        #[inline]
        pub fn is_stop(&self) -> bool { matches!(self, Self::Stop) }
    };
}

/// Implements all the inner-by-references for the [`NextElem`]-variants.
///
/// # Variants
/// - `next_elem_checks_impl($name:ident)`
///   - `$name`: The name of the type for which to implement them.
/// - `next_elem_checks_impl($($l:lifetime),+), $name:ident)`
///   - `$l`: A list of lifetimes for this type.
///   - `$name`: The name of the type for which to implement them.
macro_rules! next_elem_ref_impl {
    ($name:ident) => {
        impl $name {
            next_elem_ref_impl!(body_impl $name);
        }
        impl<'e_> From<&'e_ $name> for NextElemRef<'e_> {
            #[inline]
            fn from(value: &'e_ $name) -> NextElemRef<'e_> { value.as_ref() }
        }
    };
    ($($l:lifetime),+, $name:ident) => {
        impl<$($l),+> $name<$($l),+> {
            next_elem_ref_impl!(body_impl $name);
        }
        impl<'e_, $($l),+> From<&'e_ $name<$($l),+>> for NextElemRef<'e_> {
            #[inline]
            fn from(value: &'e_ $name<$($l),+>) -> NextElemRef<'e_> { value.as_ref() }
        }
    };



    // Private
    (body_impl $name:ident) => {
        #[doc = concat!("Returns the inner next graph element.\n\n# Returns\nA reference to the [`Elem`] that is contained within.\n\n#Panics\nThis function panics if we are not a [`Self::Elem`](", stringify!($name), "::Elem).")]
        #[inline]
        pub fn elem(&self) -> &Elem { if let Self::Elem(e) = self { e } else { panic!(concat!("Cannot unwrap {:?} as a ", stringify!($name), "::Elem"), self.variant()); } }

        #[doc = concat!("Return a [`NextElemRef`] from this ", stringify!($name), ".\n\n# Returns\nA [`NextElemRef`] that contains a reference to the element in Self, if any.")]
        #[inline]
        pub fn as_ref(&self) -> NextElemRef {
            match self {
                Self::Elem(e) => NextElemRef::Elem(e),
                Self::Next    => NextElemRef::Next,
                Self::Return  => NextElemRef::Return,
                Self::Stop    => NextElemRef::Stop,
            }
        }
    };
}

/// Implements all the inner-by-mutable-references for the [`NextElem`]-variants.
///
/// # Variants
/// - `next_elem_checks_impl($name:ident)`
///   - `$name`: The name of the type for which to implement them.
/// - `next_elem_checks_impl($($l:lifetime),+), $name:ident)`
///   - `$l`: A list of lifetimes for this type.
///   - `$name`: The name of the type for which to implement them.
macro_rules! next_elem_mut_impl {
    ($name:ident) => {
        impl $name {
            next_elem_mut_impl!(body_impl $name);
        }
        impl<'e_> From<&'e_ mut $name> for NextElemMut<'e_> {
            #[inline]
            fn from(value: &'e_ mut $name) -> NextElemMut<'e_> { value.as_mut() }
        }
    };
    ($($l:lifetime),+, $name:ident) => {
        impl<$($l),+> $name<$($l),+> {
            next_elem_mut_impl!(body_impl $name);
        }
        impl<'e_, $($l),+> From<&'e_ mut $name<$($l),+>> for NextElemMut<'e_> {
            #[inline]
            fn from(value: &'e_ mut $name<$($l),+>) -> NextElemMut<'e_> { value.as_mut() }
        }
    };



    // Private
    (body_impl $name:ident) => {
        #[doc = concat!("Returns the inner next graph element.\n\n# Returns\nA mutable reference to the [`Elem`] that is contained within.\n\n#Panics\nThis function panics if we are not a [`Self::Elem`](", stringify!($name), "::Elem).")]
        #[inline]
        pub fn elem_mut(&mut self) -> &mut Elem { if let Self::Elem(e) = self { e } else { panic!(concat!("Cannot unwrap {:?} as a ", stringify!($name), "::Elem"), self.variant()); } }

        #[doc = concat!("Return a [`NextElemMut`] from this ", stringify!($name), ".\n\n# Returns\nA [`NextElemMut`] that contains a mutable reference to the element in Self, if any.")]
        #[inline]
        pub fn as_mut(&mut self) -> NextElemMut {
            match self {
                Self::Elem(e) => NextElemMut::Elem(e),
                Self::Next    => NextElemMut::Next,
                Self::Return  => NextElemMut::Return,
                Self::Stop    => NextElemMut::Stop,
            }
        }
    };
}

/// Implements all the into-inner for the [`NextElem`]-variants.
///
/// # Variants
/// - `next_elem_checks_impl($name:ident)`
///   - `$name`: The name of the type for which to implement them.
macro_rules! next_elem_into_impl {
    ($name:ident) => {
        impl $name {
            #[doc = concat!("Returns the inner next graph element.\n\n# Returns\nThe [`Elem`] that is contained within.\n\n#Panics\nThis function panics if we are not a [`Self::Elem`](", stringify!($name), "::Elem).")]
            #[inline]
            pub fn into_elem(self) -> Elem { if let Self::Elem(e) = self { e } else { panic!(concat!("Cannot unwrap {:?} as a ", stringify!($name), "::Elem"), self.variant()); } }
        }
    };
}





/***** AUXILLARY *****/
/// Describes the next node from the current one; which is either the node or a particular terminator that was reached.
///
/// This version provides ownership of the next element. See [`NextElemRef`] for a shared reference, or [`NextElemMut`] for a mutable reference.
#[derive(Clone, Debug, EnumDebug)]
pub enum NextElem {
    /// An element is next.
    Elem(Elem),
    /// An [`Elem::Next`]-terminator was encountered.
    Next,
    /// An [`Elem::Return`]-terminator was encountered.
    Return,
    /// An [`Elem::Stop`]-terminator was encountered.
    Stop,
}
next_elem_checks_impl!(NextElem);
next_elem_ref_impl!(NextElem);
next_elem_mut_impl!(NextElem);
next_elem_into_impl!(NextElem);

/// Describes the next node from the current one; which is either the node or a particular terminator that was reached.
///
/// This version provides a shared reference of the next element. See [`NextElemRef`] for ownership, or [`NextElemMut`] for a mutable reference.
#[derive(Clone, Copy, Debug, EnumDebug)]
pub enum NextElemRef<'e> {
    /// An element is next.
    Elem(&'e Elem),
    /// An [`Elem::Next`]-terminator was encountered.
    Next,
    /// An [`Elem::Return`]-terminator was encountered.
    Return,
    /// An [`Elem::Stop`]-terminator was encountered.
    Stop,
}
next_elem_checks_impl!('e, NextElemRef);
next_elem_ref_impl!('e, NextElemRef);

/// Describes the next node from the current one; which is either the node or a particular terminator that was reached.
///
/// This version provides a mutable reference of the next element. See [`NextElemRef`] for ownership, or [`NextElemRef`] for a shared reference.
#[derive(Debug, EnumDebug)]
pub enum NextElemMut<'e> {
    /// An element is next.
    Elem(&'e mut Elem),
    /// An [`Elem::Next`]-terminator was encountered.
    Next,
    /// An [`Elem::Return`]-terminator was encountered.
    Return,
    /// An [`Elem::Stop`]-terminator was encountered.
    Stop,
}
next_elem_checks_impl!('e, NextElemMut);
next_elem_ref_impl!('e, NextElemMut);
next_elem_mut_impl!('e, NextElemMut);





/***** AUXILLARY DATA *****/
/// Defines how a user looks like.
#[derive(Clone, Debug)]
pub struct User {
    /// The name of the user.
    pub name:     String,
    /// Any metadata attached to the user. Note: may need to be populated by the checker!
    pub metadata: Vec<Metadata>,
}

/// Defines the metadata of a particular **function** (not task).
#[derive(Clone, Debug)]
pub struct Function {
    /// The name of the function.
    pub name: String,
}

/// Defines a representation of a dataset.
#[derive(Clone, Debug)]
pub struct Dataset {
    /// The name of the dataset.
    pub name:     String,
    /// The place that we get it from. No transfer is necessary if this is the place of task execution.
    pub from:     Option<Location>,
    /// Any metadata attached to the dataset. Note: may need to be populated by the checker!
    pub metadata: Vec<Metadata>,
}

/// Represents a "tag" and everything we need to know.
#[derive(Clone, Debug)]
pub struct Metadata {
    /// The tag itself.
    pub tag: String,
    /// The namespace where the tag may be found. Represents the "owner", or the "definer" of the tag.
    pub namespace: String,
    /// The signature verifying this metadata. Represents the "assigner", or the "user" of the tag.
    pub signature: String,
    /// A flag stating whether the signature is valid. If [`None`], means this hasn't been validated yet.
    pub signature_valid: Option<bool>,
}





/***** LIBRARY *****/
/// Defines the workflow's toplevel view.
#[derive(Clone, Debug)]
pub struct Workflow {
    /// Defines the first node in the workflow.
    pub start: Elem,
    /// The functions part of this workflow. These are [`Rc`]-pointers, as they occur naturally within the workflow as well.
    pub funcs: HashMap<usize, (Function, FunctionBody)>,

    /// The user instigating this workflow (and getting the result, if any).
    pub user:      User,
    /// The metadata associated with this workflow as a whole.
    pub metadata:  Vec<Metadata>,
    /// The signature verifying this workflow. Is this needed???.
    pub signature: String,
}



/// Defines an element in the graph. This is either a _Node_, which defines a task execution, or an _Edge_, which defines how next tasks may be reached.
#[derive(Clone, Debug, EnumDebug)]
pub enum Elem {
    // Nodes
    /// Defines a task, which is like a [linear edge](Elem::Linear) but with a task to execute.
    Task(ElemTask),

    // Edges
    /// Defines an edge that connects to multiple next graph-branches of which only _one_ must be taken. Note that, because we don't include dynamic control flow information, we don't know _which_ will be taken.
    Branch(ElemBranch),
    /// Defines an edge that connects to multiple next graph-branches of which _all_ must be taken _concurrently_.
    Parallel(ElemParallel),
    /// Defines an edge that repeats a particular branch an unknown amount of times.
    Loop(ElemLoop),
    /// Calls another stream of edges, then continues onwards.
    Call(ElemCall),

    // Terminators
    /// Defines that the next element to execute is given by the parent `next`-field.
    ///
    /// If occuring in a function, it means a return without value.
    Next,
    /// Defines that the next element to execute is given by the parent `next`-field, but with some value.
    ///
    /// If occuring in the main, it means a value is returned from the workflow.
    Return,
    /// Defines that no more execution takes place.
    Stop,
}
impl Elem {
    /// Retrieves the `next` element of ourselves.
    ///
    /// If this Elem is a terminating element, then it returns which of the ones is reached.
    ///
    /// # Returns
    /// A [`NextElemRef`]-enum that either gives the next element in [`NextElemRef::Elem`], or a terminator as [`NextElemRef::Next`] or [`NextElemRef::Stop`].
    pub fn next(&self) -> NextElemRef {
        match self {
            Self::Task(ElemTask { next, .. }) => NextElemRef::Elem(next),

            Self::Branch(ElemBranch { next, .. })
            | Self::Parallel(ElemParallel { next, .. })
            | Self::Loop(ElemLoop { next, .. })
            | Self::Call(ElemCall { next, .. }) => NextElemRef::Elem(next),

            Self::Next => NextElemRef::Next,
            Self::Return => NextElemRef::Return,
            Self::Stop => NextElemRef::Stop,
        }
    }

    /// Retrieves the `next` element of ourselves.
    ///
    /// If this Elem is a terminating element, then it returns which of the ones is reached.
    ///
    /// # Returns
    /// A [`NextElemMut`]-enum that either gives the next element in [`NextElemMut::Elem`], or a terminator as [`NextElemMut::Next`] or [`NextElemMut::Stop`].
    pub fn next_mut(&mut self) -> NextElemMut {
        match self {
            Self::Task(ElemTask { next, .. }) => NextElemMut::Elem(next),

            Self::Branch(ElemBranch { next, .. })
            | Self::Parallel(ElemParallel { next, .. })
            | Self::Loop(ElemLoop { next, .. })
            | Self::Call(ElemCall { next, .. }) => NextElemMut::Elem(next),

            Self::Next => NextElemMut::Next,
            Self::Return => NextElemMut::Return,
            Self::Stop => NextElemMut::Stop,
        }
    }

    /// Retrieves the `next` element of ourselves.
    ///
    /// If this Elem is a terminating element, then it returns which of the ones is reached.
    ///
    /// # Returns
    /// A [`NextElem`]-enum that either gives the next element in [`NextElem::Elem`], or a terminator as [`NextElem::Next`] or [`NextElem::Stop`].
    pub fn into_next(self) -> NextElem {
        match self {
            Self::Task(ElemTask { next, .. }) => NextElem::Elem(*next),

            Self::Branch(ElemBranch { next, .. })
            | Self::Parallel(ElemParallel { next, .. })
            | Self::Loop(ElemLoop { next, .. })
            | Self::Call(ElemCall { next, .. }) => NextElem::Elem(*next),

            Self::Next => NextElem::Next,
            Self::Return => NextElem::Return,
            Self::Stop => NextElem::Stop,
        }
    }
}

/// Defines the only node in the graph consisting of [`Elem`]s.
///
/// Yeah so basically represents a task execution, with all checker-relevant information.
#[derive(Clone, Debug)]
pub struct ElemTask {
    /// The name of the task to execute
    pub name:    String,
    /// The name of the package in which to find the task.
    pub package: String,
    /// The version number of the package in which to find the task.
    pub version: Version,
    /// The hash of the container, specifically.
    pub hash:    Option<String>,

    /// Any input datasets used by the task.
    pub input:  Vec<Dataset>,
    /// If there is an output dataset produced by this task, this names it.
    pub output: Option<Dataset>,

    /// The location where the task is planned to be executed, if any.
    pub location:  Option<Location>,
    /// The list of metadata belonging to this task. Note: may need to be populated by the checker!
    pub metadata:  Vec<Metadata>,
    /// The signature verifying this container.
    pub signature: String,

    /// The next graph element that this task connects to.
    pub next: Box<Elem>,
}

/// Defines a branching connection between graph [`Elem`]ents.
///
/// Or rather, defines a linear connection between two nodes, with a set of branches in between them.
#[derive(Clone, Debug)]
pub struct ElemBranch {
    /// The branches of which one _must_ be taken, but we don't know which one.
    pub branches: Vec<Elem>,
    /// The next graph element that this branching edge connects to.
    pub next:     Box<Elem>,
}

/// Defines a parallel connection between graph [`Elem`]ents.
///
/// Is like a [branch](ElemBranch), except that _all_ branches are taken _concurrently_ instead of only one.
#[derive(Clone, Debug)]
pub struct ElemParallel {
    /// The branches, _all_ of which but be taken _concurrently_.
    pub branches: Vec<Elem>,
    /// The method of joining the branches.
    pub merge:    MergeStrategy,
    /// The next graph element that this parallel edge connects to.
    pub next:     Box<Elem>,
}

/// Defines a looping connection between graph [`Elem`]ents.
///
/// Simply defines a branch that is taken repeatedly. Any condition that was there is embedded in the branching part, since that's how the branch is dynamically taken and we can't know how often any of them is taken anyway.
#[derive(Clone, Debug)]
pub struct ElemLoop {
    /// The body (and embedded condition) of the loop.
    pub body: Box<Elem>,
    /// The next graph element that this parallel edge connects to.
    pub next: Box<Elem>,
}

/// Defines a calling connection between graph [`Elem`]ents.
///
/// Refers (not defines) to a shared-ownership branch of elements that is executed before the `next`` element is continued with.
#[derive(Clone, Debug)]
pub struct ElemCall {
    /// The ID of the function we're calling.
    pub id:   usize,
    /// The set of elements to call. Note that this may represent a concrete body of elements _or_ some reference to a builtin.
    pub func: FunctionBody,
    /// The next graph element that this calling edge connects to.
    pub next: Box<Elem>,
}
/// The possibilities that make up a function body.
#[derive(Clone, Debug, EnumDebug)]
pub enum FunctionBody {
    /// It's a concrete tree of elements.
    Elems(Rc<RefCell<Elem>>),
    /// It's a builtin with a given name.
    Builtin,
}